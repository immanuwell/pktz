package tui

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/immanuwell/pktz/internal/collector"
)

const (
	tcpdumpMaxLines = 500
	tcpdumpMaxPorts = 20 // BPF filter length guard
)

// tcpdumpLineMsg carries one stdout line from the tcpdump subprocess.
// The scanner pointer lets the handler discard lines from a stale session.
type tcpdumpLineMsg struct {
	scanner *bufio.Scanner
	line    string
}

// tcpdumpStopMsg fires when the tcpdump subprocess exits.
type tcpdumpStopMsg struct {
	scanner *bufio.Scanner
}

// tcpdumpState holds the running subprocess and its output ring buffer.
type tcpdumpState struct {
	cmd    *exec.Cmd
	stdout *bufio.Scanner
	lines  []string
	ports  map[uint16]bool
	scroll int    // 0 = pinned to bottom; positive = lines scrolled up from bottom
	errMsg string // non-empty when tcpdump could not be started
}

func (s *tcpdumpState) stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	s.cmd = nil
	s.stdout = nil
}

func (s *tcpdumpState) appendLine(line string) {
	s.lines = append(s.lines, line)
	if len(s.lines) > tcpdumpMaxLines {
		s.lines = s.lines[len(s.lines)-tcpdumpMaxLines:]
	}
}

// portsFromConns extracts the unique set of ports from a connection list.
func portsFromConns(conns []collector.ConnInfo) map[uint16]bool {
	ports := make(map[uint16]bool)
	for _, c := range conns {
		if c.SrcPort != 0 {
			ports[c.SrcPort] = true
		}
		if c.DstPort != 0 {
			ports[c.DstPort] = true
		}
	}
	return ports
}

// samePortSet returns true when two port sets are identical.
func samePortSet(a, b map[uint16]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for p := range a {
		if !b[p] {
			return false
		}
	}
	return true
}

// buildPortFilter builds a tcpdump BPF expression for a set of ports.
func buildPortFilter(ports map[uint16]bool) string {
	parts := make([]string, 0, tcpdumpMaxPorts)
	for p := range ports {
		parts = append(parts, fmt.Sprintf("port %d", p))
		if len(parts) >= tcpdumpMaxPorts {
			break
		}
	}
	return strings.Join(parts, " or ")
}

// startTcpdump launches tcpdump filtered by the active ports of conns.
func startTcpdump(conns []collector.ConnInfo) (*tcpdumpState, tea.Cmd) {
	ports := portsFromConns(conns)
	state := &tcpdumpState{ports: ports}

	if len(ports) == 0 {
		state.errMsg = "no active connections to filter"
		return state, nil
	}

	args := []string{"-i", "any", "-n", "-l", "--immediate-mode", buildPortFilter(ports)}
	cmd := exec.Command("tcpdump", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		state.errMsg = "tcpdump: " + err.Error()
		return state, nil
	}
	if err := cmd.Start(); err != nil {
		// Distinguish "not found" from other errors.
		if _, lookErr := exec.LookPath("tcpdump"); lookErr != nil {
			state.errMsg = "tcpdump not found — install it to use this pane"
		} else {
			state.errMsg = "tcpdump: " + err.Error()
		}
		return state, nil
	}

	scanner := bufio.NewScanner(stdout)
	state.cmd = cmd
	state.stdout = scanner
	return state, readTcpdumpLine(scanner)
}

// readTcpdumpLine returns a tea.Cmd that blocks until the next stdout line.
func readTcpdumpLine(scanner *bufio.Scanner) tea.Cmd {
	return func() tea.Msg {
		if scanner.Scan() {
			return tcpdumpLineMsg{scanner: scanner, line: scanner.Text()}
		}
		return tcpdumpStopMsg{scanner: scanner}
	}
}

// ensureTcpdumpRunning starts or restarts the tcpdump subprocess when the
// tcpdump pane is active and graphPID/ports have changed.
func (m Model) ensureTcpdumpRunning() (Model, tea.Cmd) {
	if m.graphPID == 0 {
		return m, nil
	}
	newPorts := portsFromConns(m.graphConns)
	if m.tcpdump != nil {
		if m.tcpdump.cmd != nil && samePortSet(newPorts, m.tcpdump.ports) {
			return m, nil // already running with correct ports
		}
		m.tcpdump.stop()
	}
	state, readCmd := startTcpdump(m.graphConns)
	m.tcpdump = state
	return m, readCmd
}

// handlePaneChange manages tcpdump lifecycle and focus when the active pane changes.
func (m Model) handlePaneChange(prevPane int) (tea.Model, tea.Cmd) {
	if m.detailPane == prevPane {
		return m, nil
	}
	// Stop tcpdump when leaving its pane.
	if prevPane == detailPaneTcpdump && m.tcpdump != nil {
		m.tcpdump.stop()
		m.tcpdump = nil
	}
	// Clear scroll-focus when moving to a non-scrollable pane.
	if m.detailPane != detailPaneConns && m.detailPane != detailPaneTcpdump {
		m.detailFocused = false
	}
	// Start tcpdump when entering its pane.
	if m.detailPane == detailPaneTcpdump {
		return m.ensureTcpdumpRunning()
	}
	return m, nil
}

// renderTcpdumpPane renders the tcpdump output in the detail panel.
func (m Model) renderTcpdumpPane() string {
	panelH := m.graphPanelHeight()
	if m.width <= 0 || panelH <= 0 || m.graphPID == 0 {
		return strings.Repeat("\n", panelH)
	}

	name := m.graphName
	if name == "" {
		name = fmt.Sprintf("pid %d", m.graphPID)
	}

	separator := dimStyle.Render(strings.Repeat("─", m.width))
	titleLeft := graphTitleStyle.Render(fmt.Sprintf(" ▸ %s  (pid %d)   tcpdump", name, m.graphPID))
	paneBar := m.renderPaneBar()
	titleGap := m.width - lipgloss.Width(titleLeft) - lipgloss.Width(paneBar)
	if titleGap < 1 {
		titleGap = 1
	}

	var sb strings.Builder
	sb.WriteString(separator + "\n")
	sb.WriteString(titleLeft + strings.Repeat(" ", titleGap) + paneBar + "\n")

	contentRows := panelH - 2
	if contentRows < 1 {
		contentRows = 1
	}

	writeBlank := func(n int) {
		sb.WriteString(strings.Repeat("\n", n))
	}

	if m.tcpdump == nil {
		sb.WriteString(dimStyle.Render("  starting…"))
		writeBlank(contentRows - 1)
		return sb.String()
	}
	if m.tcpdump.errMsg != "" {
		sb.WriteString(errorStyle.Render("  "+m.tcpdump.errMsg))
		writeBlank(contentRows - 1)
		return sb.String()
	}
	if len(m.tcpdump.lines) == 0 {
		sb.WriteString(dimStyle.Render("  waiting for packets…"))
		writeBlank(contentRows - 1)
		return sb.String()
	}

	scroll := m.tcpdump.scroll
	lines := m.tcpdump.lines

	// Reserve one row for the scroll hint when scrolled.
	displayRows := contentRows
	if scroll > 0 {
		displayRows = contentRows - 1
		if displayRows < 1 {
			displayRows = 1
		}
	}

	end := len(lines) - scroll
	if end < 0 {
		end = 0
	}
	start := end - displayRows
	if start < 0 {
		start = 0
	}

	avail := m.width - 2
	if avail < 4 {
		avail = 4
	}
	for i := start; i < end; i++ {
		line := lines[i]
		if runes := []rune(line); len(runes) > avail {
			line = string(runes[:avail-1]) + "…"
		}
		sb.WriteString("  " + dimStyle.Render(line) + "\n")
	}

	if scroll > 0 {
		hint := fmt.Sprintf("  ↑↓ j/k scroll  [%d / %d]  esc:bottom", len(lines)-scroll, len(lines))
		sb.WriteString(helpStyle.Render(hint) + "\n")
	}

	return sb.String()
}
