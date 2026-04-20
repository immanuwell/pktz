package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/immanuwell/pktz/internal/collector"
	"github.com/immanuwell/pktz/internal/tui"
)

const version = "0.1.0"

func main() {
	ver := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *ver {
		fmt.Println("pktz", version)
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

	go c.Run()

	p := tea.NewProgram(tui.New(c), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "pktz: %v\n", err)
		os.Exit(1)
	}
}
