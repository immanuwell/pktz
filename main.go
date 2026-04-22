package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/immanuwell/pktz/internal/collector"
	"github.com/immanuwell/pktz/internal/demo"
	"github.com/immanuwell/pktz/internal/geoip"
	"github.com/immanuwell/pktz/internal/resolver"
	"github.com/immanuwell/pktz/internal/tui"
)

const version = "0.1.0"

func main() {
	ver := flag.Bool("version", false, "print version and exit")
	downloadDB := flag.Bool("download-geoip-db", false, "download DB-IP GeoLite databases (no account required) and exit")
	logMode := flag.Bool("log", false, "emit newline-delimited JSON to stdout instead of starting the TUI")
	demoMode := flag.Bool("demo", false, "anonymize all IPs and hostnames for safe screen-sharing")
	fakeProcsFlag := flag.String("fake-processes", "", "comma-separated list of fake process names to inject (implies --demo)")
	pidFlag := flag.Uint("pid", 0, "open connection detail for this PID on startup")
	appFlag := flag.String("app", "", "show only processes matching this name or path (e.g. firefox, /usr/bin/chrome)")
	flag.Parse()

	initialPID := uint32(*pidFlag)
	appFilter := normalizeAppFilter(*appFlag)

	if initialPID != 0 {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", initialPID)); err != nil {
			fmt.Fprintf(os.Stderr, "pktz: pid %d not found\n", initialPID)
			os.Exit(1)
		}
	}

	var anon *demo.Anonymizer
	if *demoMode || *fakeProcsFlag != "" {
		var names []string
		if *fakeProcsFlag != "" {
			for _, n := range strings.Split(*fakeProcsFlag, ",") {
				if n = strings.TrimSpace(n); n != "" {
					names = append(names, n)
				}
			}
		}
		var err error
		anon, err = demo.New(names)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pktz: demo init: %v\n", err)
			os.Exit(1)
		}
	}

	if *ver {
		fmt.Println("pktz", version)
		return
	}

	if *downloadDB {
		runDownload()
		return
	}

	c, err := collector.New()
	if err != nil {
		if isPermissionErr(err) {
			fmt.Fprintln(os.Stderr, "pktz: insufficient privileges to load eBPF programs.")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "  Option A — one-time setcap (no sudo ever again):")
			fmt.Fprintln(os.Stderr, "    sudo setcap cap_bpf,cap_perfmon,cap_dac_read_search+ep $(which pktz)")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "  Option B — run with sudo:")
			fmt.Fprintln(os.Stderr, "    sudo pktz")
		} else {
			fmt.Fprintf(os.Stderr, "pktz: failed to start: %v\n", err)
		}
		os.Exit(1)
	}
	defer c.Close()

	c.Poll()
	go c.Run()

	if *logMode {
		runLog(c, anon, initialPID, appFilter)
		return
	}

	res := resolver.New()

	var geo *geoip.DB
	if geoip.DBExists() {
		if db, err := geoip.Open(); err == nil {
			geo = db
			defer geo.Close()
		} else {
			fmt.Fprintf(os.Stderr, "pktz: geoip: %v (run pktz --download-geoip-db to refresh)\n", err)
		}
	}

	p := tea.NewProgram(tui.New(c, res, geo, anon, initialPID, appFilter), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "pktz: %v\n", err)
		os.Exit(1)
	}
}

// ── log mode ──────────────────────────────────────────────────────────────────

type procRecord struct {
	Type    string    `json:"type"`
	Ts      time.Time `json:"ts"`
	PID     uint32    `json:"pid"`
	Comm    string    `json:"comm"`
	RxBps   float64   `json:"rx_bps"`
	TxBps   float64   `json:"tx_bps"`
	RxBytes uint64    `json:"rx_bytes"`
	TxBytes uint64    `json:"tx_bytes"`
	Conns   int       `json:"conns"`
}

type connRecord struct {
	Type    string    `json:"type"`
	Ts      time.Time `json:"ts"`
	PID     uint32    `json:"pid"`
	Comm    string    `json:"comm"`
	SrcIP   string    `json:"src_ip"`
	SrcPort uint16    `json:"src_port"`
	DstIP   string    `json:"dst_ip"`
	DstPort uint16    `json:"dst_port"`
	Proto   string    `json:"proto"`
	State   string    `json:"state,omitempty"`
	RxBps   float64   `json:"rx_bps"`
	TxBps   float64   `json:"tx_bps"`
	RxBytes uint64    `json:"rx_bytes"`
	TxBytes uint64    `json:"tx_bytes"`
}

// runLog polls the collector every 500 ms and writes NDJSON to stdout.
// It exits silently on a broken pipe (e.g. the consumer closed the pipe).
func runLog(c *collector.Collector, anon *demo.Anonymizer, pidFilter uint32, appFilter string) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	for range ticker.C {
		now := time.Now().UTC()
		procs := c.Processes()
		if anon != nil {
			procs = anon.Processes(procs)
		}

		sort.Slice(procs, func(i, j int) bool {
			return (procs[i].RxRate + procs[i].TxRate) > (procs[j].RxRate + procs[j].TxRate)
		})

		for _, p := range procs {
			if pidFilter != 0 && p.PID != pidFilter {
				continue
			}
			if appFilter != "" && !strings.Contains(strings.ToLower(p.Comm), appFilter) {
				continue
			}
			if err := enc.Encode(procRecord{
				Type:    "process",
				Ts:      now,
				PID:     p.PID,
				Comm:    p.Comm,
				RxBps:   p.RxRate,
				TxBps:   p.TxRate,
				RxBytes: p.RxTotal,
				TxBytes: p.TxTotal,
				Conns:   p.ConnCount,
			}); err != nil {
				return // broken pipe or closed stdout — exit cleanly
			}

			var connList []collector.ConnInfo
			if anon != nil && anon.IsFakePID(p.PID) {
				connList = anon.FakeConns(p.PID)
			} else {
				connList = c.Connections(p.PID)
				if anon != nil {
					connList = anon.Conns(connList)
				}
			}
			for _, conn := range connList {
				srcIP := ""
				if conn.SrcAddr != nil {
					srcIP = conn.SrcAddr.String()
				}
				dstIP := ""
				if conn.DstAddr != nil {
					dstIP = conn.DstAddr.String()
				}
				if err := enc.Encode(connRecord{
					Type:    "conn",
					Ts:      now,
					PID:     p.PID,
					Comm:    p.Comm,
					SrcIP:   srcIP,
					SrcPort: conn.SrcPort,
					DstIP:   dstIP,
					DstPort: conn.DstPort,
					Proto:   conn.Proto,
					State:   conn.State,
					RxBps:   conn.RxRate,
					TxBps:   conn.TxRate,
					RxBytes: conn.RxTotal,
					TxBytes: conn.TxTotal,
				}); err != nil {
					return
				}
			}
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// normalizeAppFilter extracts a lowercase basename from a path, or lowercases a plain name.
// "/usr/bin/google-chrome" → "google-chrome", "Firefox" → "firefox"
func normalizeAppFilter(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "/") {
		s = filepath.Base(s)
	}
	return strings.ToLower(s)
}

func isPermissionErr(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES)
}

// ── download ──────────────────────────────────────────────────────────────────

func runDownload() {
	fmt.Println("Downloading DB-IP GeoLite databases (no account required, CC BY 4.0)…")
	if err := geoip.Download(func(msg string) { fmt.Println(msg) }); err != nil {
		fmt.Fprintf(os.Stderr, "pktz: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nDone! Databases saved to %s\n", geoip.DataDir())
	fmt.Println("Run pktz to see country flags and ASN names (press 'g' to toggle).")
}
