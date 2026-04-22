package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/immanuwell/pktz/internal/collector"
	"github.com/immanuwell/pktz/internal/demo"
)

// serveMetrics starts an HTTP server on addr that exposes a Prometheus /metrics
// endpoint. It runs in the background and never returns (logs fatal on bind error).
func serveMetrics(addr string, c *collector.Collector, anon *demo.Anonymizer, pidFilter uint32, appFilter string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		procs := c.Processes()
		if anon != nil {
			procs = anon.Processes(procs)
		}
		if pidFilter != 0 {
			procs = filterByPID(procs, pidFilter)
		}
		if appFilter != "" {
			procs = filterByApp(procs, appFilter)
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writePrometheusMetrics(w, procs)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>pktz</title></head><body>`+
			`<h2>pktz — eBPF network monitor</h2>`+
			`<p><a href="/metrics">/metrics</a></p>`+
			`</body></html>`)
	})

	fmt.Fprintf(os.Stderr, "pktz: metrics endpoint → http://%s/metrics\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "pktz: metrics: %v\n", err)
		os.Exit(1)
	}
}

// procMetricDef describes one Prometheus metric family derived from ProcessInfo.
type procMetricDef struct {
	name string
	help string
	typ  string
	val  func(collector.ProcessInfo) float64
}

var procMetricDefs = []procMetricDef{
	{
		"pktz_process_rx_bytes_per_second",
		"Current receive rate for the process in bytes per second.",
		"gauge",
		func(p collector.ProcessInfo) float64 { return p.RxRate },
	},
	{
		"pktz_process_tx_bytes_per_second",
		"Current transmit rate for the process in bytes per second.",
		"gauge",
		func(p collector.ProcessInfo) float64 { return p.TxRate },
	},
	{
		"pktz_process_rx_bytes_total",
		"Total bytes received by the process since tracking began.",
		"counter",
		func(p collector.ProcessInfo) float64 { return float64(p.RxTotal) },
	},
	{
		"pktz_process_tx_bytes_total",
		"Total bytes transmitted by the process since tracking began.",
		"counter",
		func(p collector.ProcessInfo) float64 { return float64(p.TxTotal) },
	},
	{
		"pktz_process_connections",
		"Number of open network connections for the process.",
		"gauge",
		func(p collector.ProcessInfo) float64 { return float64(p.ConnCount) },
	},
}

func writePrometheusMetrics(w io.Writer, procs []collector.ProcessInfo) {
	for _, def := range procMetricDefs {
		fmt.Fprintf(w, "# HELP %s %s\n", def.name, def.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", def.name, def.typ)
		for _, p := range procs {
			fmt.Fprintf(w, "%s{pid=\"%d\",comm=\"%s\"} %g\n",
				def.name, p.PID, promEscape(p.Comm), def.val(p))
		}
	}
}

// promEscape sanitizes a string for use as a Prometheus label value.
func promEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func filterByPID(procs []collector.ProcessInfo, pid uint32) []collector.ProcessInfo {
	out := procs[:0:0]
	for _, p := range procs {
		if p.PID == pid {
			out = append(out, p)
		}
	}
	return out
}

func filterByApp(procs []collector.ProcessInfo, filter string) []collector.ProcessInfo {
	out := procs[:0:0]
	for _, p := range procs {
		if strings.Contains(strings.ToLower(p.Comm), filter) {
			out = append(out, p)
		}
	}
	return out
}
