// Package collector loads the pktz eBPF programs and exposes per-process
// and per-connection traffic statistics.
package collector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-18 -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86 -I../../bpf -I/usr/src/linux-headers-6.17.0-1017-oem/tools/bpf/resolve_btfids/libbpf/include" pktz ../../bpf/pktz.c

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// ProcessInfo holds aggregated traffic stats for one process.
type ProcessInfo struct {
	PID           uint32
	PPID          uint32 // parent PID; 0 if unknown
	Comm          string
	ContainerName string  // human-readable container name or short ID; "" for host processes
	RxRate        float64 // bytes/sec since last poll
	TxRate        float64
	RxTotal       uint64
	TxTotal       uint64
	TxPktsTotal   uint64  // cumulative TX packets since pktz started
	RetransPkts   uint64  // TCP segments retransmitted since pktz started
	RxPPS         float64 // packets/sec since last poll
	TxPPS         float64
	ConnCount     int
}

// ConnInfo holds per-connection traffic stats.
type ConnInfo struct {
	SrcAddr net.IP
	DstAddr net.IP
	SrcPort uint16
	DstPort uint16
	Proto   string
	State   string  // e.g. "ESTABLISHED", "LISTEN", "" for UDP
	RxRate  float64 // zero when no eBPF data available yet
	TxRate  float64
	RxTotal uint64
	TxTotal uint64
	RxPPS   float64 // packets/sec; zero when no eBPF data available yet
	TxPPS   float64
}

type procSnapshot struct {
	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
	at        time.Time
}

type connSnapshot struct {
	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
	at        time.Time
}

// ebpfConnKey mirrors pktzConnKey but is comparable so it can be used as a map key.
type ebpfConnKey struct {
	pid    uint32
	saddr  [16]byte
	daddr  [16]byte
	sport  uint16
	dport  uint16
	proto  uint8
	family uint8
}

// Collector manages the eBPF programs and aggregates traffic data.
type Collector struct {
	objs  pktzObjects
	links []link.Link

	mu          sync.RWMutex
	procs       map[uint32]*ProcessInfo
	connsByPID  map[uint32][]ConnInfo
	history     map[uint32][]HistoryEntry

	prevProc       map[uint32]procSnapshot
	prevConn       map[ebpfConnKey]connSnapshot
	containerNames map[string]string // container ID → resolved name; populated lazily

	prevIface map[string]ifaceSnapshot
	ifaces    []IfaceInfo // updated each poll; read via Interfaces()
}

// New loads the eBPF programs and attaches kprobes.
func New() (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs pktzObjects
	if err := loadPktzObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	c := &Collector{
		objs:           objs,
		procs:          make(map[uint32]*ProcessInfo),
		connsByPID:     make(map[uint32][]ConnInfo),
		history:        make(map[uint32][]HistoryEntry),
		prevProc:       make(map[uint32]procSnapshot),
		prevConn:       make(map[ebpfConnKey]connSnapshot),
		containerNames: make(map[string]string),
		prevIface:      make(map[string]ifaceSnapshot),
	}

	// required probes — fatal if missing
	required := []struct {
		sym  string
		prog *ebpf.Program
	}{
		{"tcp_sendmsg", objs.KprobeTcpSendmsg},
		{"tcp_cleanup_rbuf", objs.KprobeTcpCleanupRbuf},
		{"udp_sendmsg", objs.KprobeUdpSendmsg},
	}
	for _, p := range required {
		l, err := link.Kprobe(p.sym, p.prog, nil)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach kprobe %s: %w", p.sym, err)
		}
		c.links = append(c.links, l)
	}

	// optional probes — silently skip if absent on this kernel
	optional := []struct {
		sym  string
		prog *ebpf.Program
	}{
		{"skb_consume_udp", objs.KprobeSkbConsumeUdp},
		{"udpv6_sendmsg", objs.KprobeUdpv6Sendmsg},
		{"tcp_retransmit_skb", objs.KprobeTcpRetransmitSkb},
	}
	for _, p := range optional {
		if l, err := link.Kprobe(p.sym, p.prog, nil); err == nil {
			c.links = append(c.links, l)
		}
	}

	return c, nil
}

// Poll performs one immediate data collection cycle.
// Call it once synchronously before starting Run so the first display is instant.
func (c *Collector) Poll() {
	c.poll()
}

// Run polls eBPF maps and /proc/net every 500 ms. Call in a goroutine.
func (c *Collector) Run() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		c.poll()
	}
}

// Close detaches probes and frees eBPF resources.
func (c *Collector) Close() {
	for _, l := range c.links {
		l.Close()
	}
	c.objs.Close()
}

// Processes returns a snapshot of all processes with open network sockets.
func (c *Collector) Processes() []ProcessInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ProcessInfo, 0, len(c.procs))
	for _, p := range c.procs {
		out = append(out, *p)
	}
	return out
}

// Interfaces returns a snapshot of active network interfaces with current rates.
func (c *Collector) Interfaces() []IfaceInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]IfaceInfo(nil), c.ifaces...)
}

// History returns up to maxHistoryLen bandwidth samples for pid, oldest first.
func (c *Collector) History(pid uint32) []HistoryEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]HistoryEntry(nil), c.history[pid]...)
}

// Connections returns all connections for a given PID.
func (c *Collector) Connections(pid uint32) []ConnInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]ConnInfo(nil), c.connsByPID[pid]...)
}

func (c *Collector) poll() {
	now := time.Now()

	// ── Step 1: /proc/net scan gives us ALL processes with open sockets ──────
	rawConns := ScanNetConnections()

	// Group by PID and build process map seeded from /proc
	pidConns := make(map[uint32][]ProcConn, len(rawConns))
	for _, rc := range rawConns {
		pidConns[rc.PID] = append(pidConns[rc.PID], rc)
	}

	newProcs := make(map[uint32]*ProcessInfo, len(pidConns))
	for pid, conns := range pidConns {
		newProcs[pid] = &ProcessInfo{
			PID:           pid,
			PPID:          ppidFromProc(pid),
			Comm:          commFromProc(pid),
			ContainerName: c.resolveContainerName(readContainerID(pid)),
			ConnCount:     len(conns),
		}
	}

	// ── Step 2: eBPF process map — overlay rates onto existing entries ────────
	var pKey uint32
	var pVal pktzProcStats
	iter := c.objs.ProcStatsMap.Iterate()
	for iter.Next(&pKey, &pVal) {
		pid := pKey
		prev := c.prevProc[pid]
		dt := now.Sub(prev.at).Seconds()

		var rxRate, txRate, rxPPS, txPPS float64
		if dt > 0 && !prev.at.IsZero() {
			rxRate = clampPositive(float64(pVal.RxBytes-prev.rxBytes) / dt)
			txRate = clampPositive(float64(pVal.TxBytes-prev.txBytes) / dt)
			rxPPS = clampPositive(float64(pVal.RxPackets-prev.rxPackets) / dt)
			txPPS = clampPositive(float64(pVal.TxPackets-prev.txPackets) / dt)
		}
		c.prevProc[pid] = procSnapshot{
			txBytes: pVal.TxBytes, rxBytes: pVal.RxBytes,
			txPackets: pVal.TxPackets, rxPackets: pVal.RxPackets,
			at: now,
		}

		p, ok := newProcs[pid]
		if !ok {
			// Process has traffic in the eBPF map but no open sockets in /proc/net.
			// Only show it if the PID still exists — otherwise the process has exited
			// and we'd be displaying a ghost from the eBPF LRU map.
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
				continue
			}
			p = &ProcessInfo{PID: pid, PPID: ppidFromProc(pid), Comm: commFromProc(pid), ContainerName: c.resolveContainerName(readContainerID(pid))}
			if comm := nullTermString(pVal.Comm[:]); comm != "" {
				p.Comm = comm
			}
			newProcs[pid] = p
		}
		p.RxRate = rxRate
		p.TxRate = txRate
		p.RxTotal = pVal.RxBytes
		p.TxTotal = pVal.TxBytes
		p.TxPktsTotal = pVal.TxPackets
		p.RetransPkts = pVal.RetransPkts
		p.RxPPS = rxPPS
		p.TxPPS = txPPS
	}

	// ── Step 3: Build per-PID connection lists ────────────────────────────────
	// Start with what /proc/net gave us (full coverage, no rates yet).
	newConnsByPID := make(map[uint32][]ConnInfo, len(pidConns))
	for pid, rawList := range pidConns {
		cs := make([]ConnInfo, len(rawList))
		for i, rc := range rawList {
			cs[i] = ConnInfo{
				SrcAddr: rc.SrcAddr,
				DstAddr: rc.DstAddr,
				SrcPort: rc.SrcPort,
				DstPort: rc.DstPort,
				Proto:   rc.Proto,
				State:   rc.State,
			}
		}
		newConnsByPID[pid] = cs
	}

	// Overlay eBPF per-connection rates.
	var cKey pktzConnKey
	var cVal pktzConnStats
	iter2 := c.objs.ConnStatsMap.Iterate()
	for iter2.Next(&cKey, &cVal) {
		ek := ebpfConnKey{
			pid: cKey.Pid, saddr: cKey.Saddr, daddr: cKey.Daddr,
			sport: cKey.Sport, dport: cKey.Dport, proto: cKey.Proto,
			family: cKey.Family,
		}
		prev := c.prevConn[ek]
		dt := now.Sub(prev.at).Seconds()

		var rxRate, txRate, rxPPS, txPPS float64
		if dt > 0 && !prev.at.IsZero() {
			rxRate = clampPositive(float64(cVal.RxBytes-prev.rxBytes) / dt)
			txRate = clampPositive(float64(cVal.TxBytes-prev.txBytes) / dt)
			rxPPS = clampPositive(float64(cVal.RxPackets-prev.rxPackets) / dt)
			txPPS = clampPositive(float64(cVal.TxPackets-prev.txPackets) / dt)
		}
		c.prevConn[ek] = connSnapshot{
			txBytes: cVal.TxBytes, rxBytes: cVal.RxBytes,
			txPackets: cVal.TxPackets, rxPackets: cVal.RxPackets,
			at: now,
		}

		proto := "TCP"
		if cKey.Proto == 17 {
			proto = "UDP"
		}
		ebpfSrc := ebpfAddrToIP(cKey.Saddr, cKey.Family)
		ebpfDst := ebpfAddrToIP(cKey.Daddr, cKey.Family)

		// Overlay rates onto the matching /proc/net entry.
		// If there is no match the connection is stale (closed but still in the
		// eBPF LRU map) — skip it so counts stay consistent with /proc/net.
		for i := range newConnsByPID[cKey.Pid] {
			conn := &newConnsByPID[cKey.Pid][i]
			if conn.Proto == proto &&
				conn.SrcPort == cKey.Sport &&
				conn.DstPort == cKey.Dport &&
				conn.SrcAddr.Equal(ebpfSrc) &&
				conn.DstAddr.Equal(ebpfDst) {
				conn.RxRate = rxRate
				conn.TxRate = txRate
				conn.RxTotal = cVal.RxBytes
				conn.TxTotal = cVal.TxBytes
				conn.RxPPS = rxPPS
				conn.TxPPS = txPPS
				break
			}
		}
	}

	// Sync ConnCount with the actual connection list length so the main page
	// and the detail view always show the same number.
	for pid, conns := range newConnsByPID {
		if p, ok := newProcs[pid]; ok {
			p.ConnCount = len(conns)
		}
	}

	// Append one history entry per active process.
	for pid, p := range newProcs {
		h := c.history[pid]
		h = append(h, HistoryEntry{RxRate: p.RxRate, TxRate: p.TxRate, PPS: p.RxPPS + p.TxPPS})
		if len(h) > maxHistoryLen {
			h = h[len(h)-maxHistoryLen:]
		}
		c.history[pid] = h
	}

	newIfaces := c.pollIfaces(now)

	c.mu.Lock()
	c.procs = newProcs
	c.connsByPID = newConnsByPID
	c.ifaces = newIfaces
	c.mu.Unlock()
}

// ebpfAddrToIP converts a 16-byte address slot from an eBPF conn key to a net.IP.
// IPv4 sockets store the address in the first 4 bytes (little-endian u32, matching
// the kernel's skc_rcv_saddr layout on x86); IPv6 sockets use all 16 bytes in
// network (big-endian) order directly from skc_v6_rcv_saddr.in6_u.u6_addr8.
func ebpfAddrToIP(addr [16]byte, family uint8) net.IP {
	if family == 2 { // AF_INET
		return net.IP{addr[0], addr[1], addr[2], addr[3]}
	}
	ip := make(net.IP, 16)
	copy(ip, addr[:])
	return ip
}

func clampPositive(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

func nullTermString(b []int8) string {
	bs := make([]byte, len(b))
	for i, v := range b {
		if v == 0 {
			bs = bs[:i]
			break
		}
		bs[i] = byte(v)
	}
	return strings.TrimSpace(string(bs))
}

// resolveContainerName maps a 64-char container ID to a human-readable name.
// It tries the Docker socket on first sight; falls back to the short 12-char ID.
// Results are cached for the lifetime of the Collector.
func (c *Collector) resolveContainerName(containerID string) string {
	if containerID == "" {
		return ""
	}
	if name, ok := c.containerNames[containerID]; ok {
		return name
	}
	name := lookupDockerName(containerID)
	if name == "" {
		name = containerID[:12]
	}
	c.containerNames[containerID] = name
	return name
}

func commFromProc(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("pid%d", pid)
	}
	return strings.TrimSpace(string(data))
}

// ppidFromProc reads the parent PID from /proc/<pid>/stat.
// Format: "pid (comm) state ppid ..." — we skip past the last ')' to handle
// comm names that contain spaces or parentheses.
func ppidFromProc(pid uint32) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[idx+1:])
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.ParseUint(fields[1], 10, 32)
	return uint32(n)
}
