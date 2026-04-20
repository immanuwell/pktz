// Package collector loads the pktz eBPF programs and exposes per-process
// and per-connection traffic statistics.
package collector

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip-18 -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86 -I../../bpf -I/usr/src/linux-headers-6.17.0-1017-oem/tools/bpf/resolve_btfids/libbpf/include" pktz ../../bpf/pktz.c

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// ProcessInfo holds aggregated traffic stats for one process.
type ProcessInfo struct {
	PID       uint32
	Comm      string
	RxRate    float64 // bytes/sec since last poll
	TxRate    float64
	RxTotal   uint64
	TxTotal   uint64
	ConnCount int
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
}

type procSnapshot struct {
	txBytes uint64
	rxBytes uint64
	at      time.Time
}

type connSnapshot struct {
	txBytes uint64
	rxBytes uint64
	at      time.Time
}

// ebpfConnKey mirrors pktzConnKey but is comparable so it can be used as a map key.
type ebpfConnKey struct {
	pid   uint32
	saddr uint32
	daddr uint32
	sport uint16
	dport uint16
	proto uint8
}

// Collector manages the eBPF programs and aggregates traffic data.
type Collector struct {
	objs  pktzObjects
	links []link.Link

	mu          sync.RWMutex
	procs       map[uint32]*ProcessInfo
	connsByPID  map[uint32][]ConnInfo

	prevProc map[uint32]procSnapshot
	prevConn map[ebpfConnKey]connSnapshot
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
		objs:        objs,
		procs:       make(map[uint32]*ProcessInfo),
		connsByPID:  make(map[uint32][]ConnInfo),
		prevProc:    make(map[uint32]procSnapshot),
		prevConn:    make(map[ebpfConnKey]connSnapshot),
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
	}
	for _, p := range optional {
		if l, err := link.Kprobe(p.sym, p.prog, nil); err == nil {
			c.links = append(c.links, l)
		}
	}

	return c, nil
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
			PID:       pid,
			Comm:      commFromProc(pid),
			ConnCount: len(conns),
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

		var rxRate, txRate float64
		if dt > 0 && !prev.at.IsZero() {
			rxRate = clampPositive(float64(pVal.RxBytes-prev.rxBytes) / dt)
			txRate = clampPositive(float64(pVal.TxBytes-prev.txBytes) / dt)
		}
		c.prevProc[pid] = procSnapshot{txBytes: pVal.TxBytes, rxBytes: pVal.RxBytes, at: now}

		p, ok := newProcs[pid]
		if !ok {
			// eBPF knows about this PID (recent traffic) but it has no open sockets
			// in /proc/net right now (e.g., short-lived connection); show it anyway.
			p = &ProcessInfo{PID: pid, Comm: commFromProc(pid)}
			if comm := nullTermString(pVal.Comm[:]); comm != "" {
				p.Comm = comm
			}
			newProcs[pid] = p
		}
		p.RxRate = rxRate
		p.TxRate = txRate
		p.RxTotal = pVal.RxBytes
		p.TxTotal = pVal.TxBytes
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
		}
		prev := c.prevConn[ek]
		dt := now.Sub(prev.at).Seconds()

		var rxRate, txRate float64
		if dt > 0 && !prev.at.IsZero() {
			rxRate = clampPositive(float64(cVal.RxBytes-prev.rxBytes) / dt)
			txRate = clampPositive(float64(cVal.TxBytes-prev.txBytes) / dt)
		}
		c.prevConn[ek] = connSnapshot{txBytes: cVal.TxBytes, rxBytes: cVal.RxBytes, at: now}

		proto := "TCP"
		if cKey.Proto == 17 {
			proto = "UDP"
		}
		ebpfSrc := intToIP(cKey.Saddr)
		ebpfDst := intToIP(cKey.Daddr)

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

	c.mu.Lock()
	c.procs = newProcs
	c.connsByPID = newConnsByPID
	c.mu.Unlock()
}

func intToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
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

func commFromProc(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("pid%d", pid)
	}
	return strings.TrimSpace(string(data))
}
