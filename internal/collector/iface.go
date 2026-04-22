package collector

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IfaceInfo holds the current traffic rates and link speed for one network interface.
type IfaceInfo struct {
	Name     string
	RxRate   float64 // bytes/sec
	TxRate   float64 // bytes/sec
	SpeedBps uint64  // link capacity in bytes/sec; 0 = unknown
}

type ifaceSnapshot struct {
	rxBytes uint64
	txBytes uint64
	at      time.Time
}

// skipIface returns true for interfaces that should never appear in the bar:
// loopback and per-container veth pairs (the docker0 bridge itself is kept).
func skipIface(name string) bool {
	return name == "lo" || strings.HasPrefix(name, "veth")
}

// ifaceOperState reads /sys/class/net/<name>/operstate.
// Returns "" on error.
func ifaceOperState(name string) string {
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/operstate", name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ifaceSpeedBps reads /sys/class/net/<name>/speed (in Mbps) and converts to
// bytes/sec. Returns 0 when the file is absent, contains "N/A", or is <= 0
// (Linux reports -1 for disconnected / virtual links).
func ifaceSpeedBps(name string) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/speed", name))
	if err != nil {
		return 0
	}
	mbps, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || mbps <= 0 {
		return 0
	}
	return uint64(mbps) * 125_000 // Mbps → bytes/sec (1 Mbps = 125 000 B/s)
}

// readNetDev parses /proc/net/dev and returns a map of
// interface name → [rxBytes, txBytes].
func readNetDev() map[string][2]uint64 {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()

	m := make(map[string][2]uint64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue // header lines
		}
		name := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		m[name] = [2]uint64{rx, tx}
	}
	return m
}

// pollIfaces samples /proc/net/dev, computes per-interface rates against the
// previous snapshot, and returns a slice sorted by combined rate descending.
// Called from poll(); prevIface is only ever accessed from that goroutine.
func (c *Collector) pollIfaces(now time.Time) []IfaceInfo {
	devStats := readNetDev()
	if devStats == nil {
		return nil
	}

	var result []IfaceInfo
	for name, stats := range devStats {
		if skipIface(name) {
			continue
		}
		if ifaceOperState(name) == "down" {
			continue
		}
		rxBytes, txBytes := stats[0], stats[1]
		if rxBytes == 0 && txBytes == 0 {
			continue // interface has never carried traffic
		}

		var rxRate, txRate float64
		prev := c.prevIface[name]
		if !prev.at.IsZero() {
			dt := now.Sub(prev.at).Seconds()
			if dt > 0 {
				rxRate = clampPositive(float64(rxBytes-prev.rxBytes) / dt)
				txRate = clampPositive(float64(txBytes-prev.txBytes) / dt)
			}
		}
		c.prevIface[name] = ifaceSnapshot{rxBytes: rxBytes, txBytes: txBytes, at: now}

		result = append(result, IfaceInfo{
			Name:     name,
			RxRate:   rxRate,
			TxRate:   txRate,
			SpeedBps: ifaceSpeedBps(name),
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].RxRate+result[i].TxRate > result[j].RxRate+result[j].TxRate
	})
	return result
}
