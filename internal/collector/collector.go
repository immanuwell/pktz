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
	RxRate  float64
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

// Collector manages the eBPF programs and aggregates traffic data.
type Collector struct {
	objs  pktzObjects
	links []link.Link

	mu       sync.RWMutex
	procs    map[uint32]*ProcessInfo
	conns    map[pktzConnKey]*ConnInfo

	prevProc map[uint32]procSnapshot
	prevConn map[pktzConnKey]connSnapshot
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
		objs:     objs,
		procs:    make(map[uint32]*ProcessInfo),
		conns:    make(map[pktzConnKey]*ConnInfo),
		prevProc: make(map[uint32]procSnapshot),
		prevConn: make(map[pktzConnKey]connSnapshot),
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

	// optional probes — silently skip if the symbol is absent on this kernel
	optional := []struct {
		sym  string
		prog *ebpf.Program
	}{
		{"skb_consume_udp", objs.KprobeSkbConsumeUdp},
	}
	for _, p := range optional {
		l, err := link.Kprobe(p.sym, p.prog, nil)
		if err == nil {
			c.links = append(c.links, l)
		}
	}

	return c, nil
}

// Run polls eBPF maps every 500 ms. Call in a goroutine.
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

// Processes returns a snapshot of per-process stats sorted by caller.
func (c *Collector) Processes() []ProcessInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ProcessInfo, 0, len(c.procs))
	for _, p := range c.procs {
		out = append(out, *p)
	}
	return out
}

// Connections returns per-connection stats for a given PID.
func (c *Collector) Connections(pid uint32) []ConnInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []ConnInfo
	for k, v := range c.conns {
		if k.Pid == pid {
			out = append(out, *v)
		}
	}
	return out
}

func (c *Collector) poll() {
	now := time.Now()

	// --- process map ---
	newProcs := make(map[uint32]*ProcessInfo)
	var pKey uint32
	var pVal pktzProcStats
	iter := c.objs.ProcStatsMap.Iterate()
	for iter.Next(&pKey, &pVal) {
		pid := pKey
		comm := nullTermString(pVal.Comm[:])

		// Enrich comm from /proc if short or empty
		if comm == "" {
			comm = commFromProc(pid)
		}

		prev := c.prevProc[pid]
		dt := now.Sub(prev.at).Seconds()
		var rxRate, txRate float64
		if dt > 0 && prev.at != (time.Time{}) {
			rxRate = float64(pVal.RxBytes-prev.rxBytes) / dt
			txRate = float64(pVal.TxBytes-prev.txBytes) / dt
			if rxRate < 0 {
				rxRate = 0
			}
			if txRate < 0 {
				txRate = 0
			}
		}

		newProcs[pid] = &ProcessInfo{
			PID:     pid,
			Comm:    comm,
			RxRate:  rxRate,
			TxRate:  txRate,
			RxTotal: pVal.RxBytes,
			TxTotal: pVal.TxBytes,
		}
		c.prevProc[pid] = procSnapshot{txBytes: pVal.TxBytes, rxBytes: pVal.RxBytes, at: now}
	}

	// --- connection map ---
	newConns := make(map[pktzConnKey]*ConnInfo)
	var cKey pktzConnKey
	var cVal pktzConnStats
	iter2 := c.objs.ConnStatsMap.Iterate()
	for iter2.Next(&cKey, &cVal) {
		prev := c.prevConn[cKey]
		dt := now.Sub(prev.at).Seconds()
		var rxRate, txRate float64
		if dt > 0 && prev.at != (time.Time{}) {
			rxRate = float64(cVal.RxBytes-prev.rxBytes) / dt
			txRate = float64(cVal.TxBytes-prev.txBytes) / dt
			if rxRate < 0 {
				rxRate = 0
			}
			if txRate < 0 {
				txRate = 0
			}
		}

		proto := "TCP"
		if cKey.Proto == 17 {
			proto = "UDP"
		}

		newConns[cKey] = &ConnInfo{
			SrcAddr: intToIP(cKey.Saddr),
			DstAddr: intToIP(cKey.Daddr),
			SrcPort: cKey.Sport,
			DstPort: cKey.Dport,
			Proto:   proto,
			RxRate:  rxRate,
			TxRate:  txRate,
			RxTotal: cVal.RxBytes,
			TxTotal: cVal.TxBytes,
		}
		c.prevConn[cKey] = connSnapshot{txBytes: cVal.TxBytes, rxBytes: cVal.RxBytes, at: now}

		// Tally connection count on process
		if p, ok := newProcs[cKey.Pid]; ok {
			p.ConnCount++
		}
	}

	c.mu.Lock()
	c.procs = newProcs
	c.conns = newConns
	c.mu.Unlock()
}

func intToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
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
