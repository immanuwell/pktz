package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/immanuwell/pktz/internal/collector"
	"github.com/immanuwell/pktz/internal/geoip"
	"github.com/immanuwell/pktz/internal/resolver"
	"github.com/immanuwell/pktz/internal/tui"
)

const version = "0.1.0"

func main() {
	ver := flag.Bool("version", false, "print version and exit")
	downloadDB := flag.Bool("download-geoip-db", false, "download DB-IP GeoLite databases (no account required) and exit")
	flag.Parse()

	if *ver {
		fmt.Println("pktz", version)
		return
	}

	if *downloadDB {
		runDownload()
		return
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "pktz requires root privileges (sudo pktz)")
		os.Exit(1)
	}

	c, err := collector.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pktz: failed to start: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	c.Poll() // populate maps before the TUI starts so the first frame has data
	go c.Run()

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

	p := tea.NewProgram(tui.New(c, res, geo), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "pktz: %v\n", err)
		os.Exit(1)
	}
}

func runDownload() {
	fmt.Println("Downloading DB-IP GeoLite databases (no account required, CC BY 4.0)…")
	if err := geoip.Download(func(msg string) { fmt.Println(msg) }); err != nil {
		fmt.Fprintf(os.Stderr, "pktz: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nDone! Databases saved to %s\n", geoip.DataDir())
	fmt.Println("Run pktz to see country flags and ASN names (press 'g' to toggle).")
}
