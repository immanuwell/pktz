// Package tui provides the bubbletea-based terminal UI for pktz.
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/immanuwell/pktz/internal/collector"
)

// view identifies which screen is active.
type view int

const (
	viewProcessList view = iota
	viewConnDetail
)

// sortKey controls the ordering of the process list.
type sortKey int

const (
	sortByRx sortKey = iota
	sortByTx
	sortByTotal
	sortByName
	sortByPID
	sortByConn
	sortKeyCount
)

func (s sortKey) label() string {
	switch s {
	case sortByRx:
		return "RX/s"
	case sortByTx:
		return "TX/s"
	case sortByTotal:
		return "Total"
	case sortByName:
		return "Name"
	case sortByPID:
		return "PID"
	case sortByConn:
		return "Conn"
	}
	return ""
}

// headerRowY is the terminal row (0-indexed) where the column headers are rendered.
// Layout: row 0 = title bar, row 1 = blank (lipgloss join + leading \n in table),
// row 2 = column headers.
const headerRowY = 2

// procListCols, procListHeaders, and procListSortKeys define the process table layout.
// Each index corresponds to one column; sortKey is what clicking that header activates.
var (
	procListCols     = []int{7, 22, 11, 11, 11, 11, 5}
	procListHeaders  = []string{"PID", "PROCESS", "RX/s", "TX/s", "TOTAL RX", "TOTAL TX", "CONN"}
	procListSortKeys = []sortKey{sortByPID, sortByName, sortByRx, sortByTx, sortByTotal, sortByTotal, sortByConn}
)

// tickMsg fires on every refresh interval.
type tickMsg time.Time

// statsMsg carries freshly fetched data from the collector.
type statsMsg struct {
	procs []collector.ProcessInfo
	conns []collector.ConnInfo
}

// Model is the root bubbletea model.
type Model struct {
	coll        *collector.Collector
	activeView  view
	procs       []collector.ProcessInfo
	conns       []collector.ConnInfo
	cursor      int
	detailPID   uint32
	detailComm  string
	width       int
	height      int
	sortBy      sortKey
	sortAsc     bool // true = A→Z / low→high, false = Z→A / high→low
	pidColW     int  // dynamic: max PID digits in current list + 2
	filterInput textinput.Model
	filtering   bool
	err         error
}

// New creates a Model backed by the given collector.
func New(c *collector.Collector) Model {
	fi := textinput.New()
	fi.Placeholder = "filter…"
	fi.CharLimit = 32

	return Model{
		coll:        c,
		sortBy:      sortByName,
		sortAsc:     true, // default: alphabetical A→Z
		pidColW:     5,    // minimum; grows dynamically with observed PIDs
		filterInput: fi,
	}
}

// --- Init ---

func (m Model) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// --- Update ---

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		return m, tea.Batch(tickCmd(), fetchStats(m.coll, m.detailPID, m.activeView))

	case statsMsg:
		m.procs = applyFilter(msg.procs, m.filterInput.Value())
		sortProcs(m.procs, m.sortBy, m.sortAsc)
		m.pidColW = calcPIDColWidth(msg.procs) // use full unfiltered list for width
		m.conns = msg.conns
		sortConns(m.conns)
		if m.cursor >= len(m.procs) && len(m.procs) > 0 {
			m.cursor = len(m.procs) - 1
		}

	case tea.MouseMsg:
		if msg.Action == tea.MouseActionRelease && msg.Button == tea.MouseButtonLeft {
			return m.handleMouseClick(msg.X, msg.Y)
		}

	case tea.KeyMsg:
		if m.filtering {
			return m.handleFilterKey(msg)
		}
		return m.handleKey(msg)

	case error:
		m.err = msg
	}
	return m, nil
}

func (m Model) handleMouseClick(x, y int) (tea.Model, tea.Cmd) {
	// Only the process list has clickable headers.
	if y != headerRowY || m.activeView != viewProcessList {
		return m, nil
	}

	// Walk column X ranges to find which header was clicked.
	// Use effective cols so the PID column width matches what was rendered.
	pos := 0
	for i, w := range m.effectiveProcCols() {
		if x >= pos && x < pos+w {
			if i < len(procListSortKeys) {
				m.applySort(procListSortKeys[i])
			}
			return m, nil
		}
		pos += w
	}
	return m, nil
}

// effectiveProcCols returns the column widths with the dynamic PID column applied.
func (m Model) effectiveProcCols() []int {
	cols := make([]int, len(procListCols))
	copy(cols, procListCols)
	cols[0] = m.pidColW
	return cols
}

// applySort sets the sort key; clicking the active key toggles direction,
// clicking a new key sets the natural direction for that column type.
func (m *Model) applySort(sk sortKey) {
	if m.sortBy == sk {
		m.sortAsc = !m.sortAsc
	} else {
		m.sortBy = sk
		// Natural direction: ascending for text/id columns, descending for rates.
		m.sortAsc = (sk == sortByName || sk == sortByPID)
	}
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit

	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}

	case "down", "j":
		if max := listLen(m) - 1; m.cursor < max {
			m.cursor++
		}

	case "enter":
		if m.activeView == viewProcessList && len(m.procs) > 0 {
			p := m.procs[m.cursor]
			m.detailPID = p.PID
			m.detailComm = p.Comm
			m.activeView = viewConnDetail
			m.cursor = 0
		}

	case "esc", "backspace":
		if m.activeView == viewConnDetail {
			m.activeView = viewProcessList
			m.cursor = 0
		}

	case "s":
		if m.activeView == viewProcessList {
			next := (m.sortBy + 1) % sortKeyCount
			m.applySort(next)
		}

	case "/":
		if m.activeView == viewProcessList {
			m.filtering = true
			m.filterInput.Focus()
			return m, textinput.Blink
		}
	}
	return m, nil
}

func (m Model) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		m.filtering = false
		m.filterInput.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.filterInput, cmd = m.filterInput.Update(msg)
	return m, cmd
}

func listLen(m Model) int {
	if m.activeView == viewConnDetail {
		return len(m.conns)
	}
	return len(m.procs)
}

func fetchStats(c *collector.Collector, pid uint32, v view) tea.Cmd {
	return func() tea.Msg {
		procs := c.Processes()
		var conns []collector.ConnInfo
		if v == viewConnDetail {
			conns = c.Connections(pid)
		}
		return statsMsg{procs: procs, conns: conns}
	}
}

// --- View ---

func (m Model) View() string {
	if m.err != nil {
		return errorStyle.Render("error: "+m.err.Error()) + "\n"
	}

	var sections []string
	sections = append(sections, m.renderHeader())
	sections = append(sections, m.renderTable())
	sections = append(sections, m.renderFooter())
	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m Model) renderHeader() string {
	left := titleStyle.Render("pktz") +
		dimStyle.Render("  network traffic monitor")

	var right string
	if m.activeView == viewConnDetail {
		right = breadcrumbStyle.Render(fmt.Sprintf(" %s  (pid %d)", m.detailComm, m.detailPID))
	} else {
		arrow := "▼"
		if m.sortAsc {
			arrow = "▲"
		}
		right = dimStyle.Render(fmt.Sprintf("sort: %s %s  [s]cycle", m.sortBy.label(), arrow))
	}

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m Model) renderTable() string {
	if m.activeView == viewConnDetail {
		return m.renderConnTable()
	}
	return m.renderProcTable()
}

func (m Model) renderProcTable() string {
	cols := m.effectiveProcCols()

	// Build header labels — annotate the active sort column with ▲ / ▼.
	headers := make([]string, len(procListHeaders))
	copy(headers, procListHeaders)
	arrow := "▼"
	if m.sortAsc {
		arrow = "▲"
	}
	for i, sk := range procListSortKeys {
		if sk == m.sortBy {
			headers[i] = clickableHeader(headers[i], arrow)
			break
		}
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(renderCells(headers, cols, headerStyle))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render(strings.Repeat("─", m.width)))
	sb.WriteString("\n")

	if len(m.procs) == 0 {
		sb.WriteString(dimStyle.Render("  waiting for network traffic…"))
		sb.WriteString("\n")
		return sb.String()
	}

	tableRows := m.height - 6
	if tableRows < 1 {
		tableRows = 1
	}

	start, end := visibleRange(m.cursor, len(m.procs), tableRows)
	for i := start; i < end; i++ {
		p := m.procs[i]
		rxS := colourRate(p.RxRate).Render(formatBytes(p.RxRate) + "/s")
		txS := colourRate(p.TxRate).Render(formatBytes(p.TxRate) + "/s")
		row := []string{
			fmt.Sprintf("%d", p.PID),
			truncate(p.Comm, cols[1]-1),
			rxS,
			txS,
			formatBytes(float64(p.RxTotal)),
			formatBytes(float64(p.TxTotal)),
			fmt.Sprintf("%d", p.ConnCount),
		}
		style := normalStyle
		prefix := "  "
		if i == m.cursor {
			style = selectedStyle
			prefix = "▶ "
		}
		sb.WriteString(style.Render(prefix + renderCells(row, cols, style)))
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m Model) renderConnTable() string {
	cols := []int{21, 21, 5, 13, 9, 9, 9, 9}
	headers := []string{"LOCAL", "REMOTE", "PROTO", "STATE", "RX/s", "TX/s", "TOTAL RX", "TOTAL TX"}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(renderCells(headers, cols, headerStyle))
	sb.WriteString("\n")
	sb.WriteString(dimStyle.Render(strings.Repeat("─", m.width)))
	sb.WriteString("\n")

	if len(m.conns) == 0 {
		sb.WriteString(dimStyle.Render("  no connections"))
		sb.WriteString("\n")
		return sb.String()
	}

	tableRows := m.height - 6
	if tableRows < 1 {
		tableRows = 1
	}

	start, end := visibleRange(m.cursor, len(m.conns), tableRows)
	for i := start; i < end; i++ {
		c := m.conns[i]
		protoStyle := protoTCPStyle
		if c.Proto == "UDP" {
			protoStyle = protoUDPStyle
		}
		rxS := colourRate(c.RxRate).Render(formatBytes(c.RxRate) + "/s")
		txS := colourRate(c.TxRate).Render(formatBytes(c.TxRate) + "/s")
		row := []string{
			fmt.Sprintf("%s:%d", c.SrcAddr, c.SrcPort),
			fmt.Sprintf("%s:%d", c.DstAddr, c.DstPort),
			protoStyle.Render(c.Proto),
			truncate(c.State, cols[3]-1),
			rxS,
			txS,
			formatBytes(float64(c.RxTotal)),
			formatBytes(float64(c.TxTotal)),
		}
		style := normalStyle
		prefix := "  "
		if i == m.cursor {
			style = selectedStyle
			prefix = "▶ "
		}
		sb.WriteString(style.Render(prefix + renderCells(row, cols, style)))
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m Model) renderFooter() string {
	var left string
	if m.filtering {
		left = filterStyle.Render("/") + " " + m.filterInput.View()
	} else if m.activeView == viewProcessList {
		left = dimStyle.Render(fmt.Sprintf("%d process(es)", len(m.procs)))
	} else {
		left = dimStyle.Render(fmt.Sprintf("%d connection(s)", len(m.conns)))
	}

	var keys string
	if m.activeView == viewProcessList {
		keys = helpStyle.Render("↑↓:nav  enter:detail  click header:sort  /:filter  s:sort  q:quit")
	} else {
		keys = helpStyle.Render("↑↓:nav  esc:back  q:quit")
	}

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(keys)
	if gap < 1 {
		gap = 1
	}
	return "\n" + left + strings.Repeat(" ", gap) + keys
}

// --- helpers ---

// clickableHeader adds a sort-direction arrow to a header label.
func clickableHeader(label, arrow string) string {
	return activeHeaderStyle.Render(label + arrow)
}

func renderCells(cells []string, widths []int, style lipgloss.Style) string {
	var sb strings.Builder
	for i, cell := range cells {
		if i >= len(widths) {
			break
		}
		w := widths[i]
		plain := lipgloss.Width(cell)
		padded := cell + strings.Repeat(" ", max(0, w-plain))
		sb.WriteString(padded)
	}
	_ = style
	return sb.String()
}

func visibleRange(cursor, total, rows int) (int, int) {
	if total == 0 {
		return 0, 0
	}
	start := cursor - rows/2
	if start < 0 {
		start = 0
	}
	end := start + rows
	if end > total {
		end = total
		start = end - rows
		if start < 0 {
			start = 0
		}
	}
	return start, end
}

func applyFilter(procs []collector.ProcessInfo, q string) []collector.ProcessInfo {
	if q == "" {
		return procs
	}
	q = strings.ToLower(q)
	out := procs[:0:0]
	for _, p := range procs {
		if strings.Contains(strings.ToLower(p.Comm), q) {
			out = append(out, p)
		}
	}
	return out
}

func sortProcs(procs []collector.ProcessInfo, by sortKey, asc bool) {
	sort.Slice(procs, func(i, j int) bool {
		a, b := procs[i], procs[j]
		var less bool
		switch by {
		case sortByTx:
			less = a.TxRate < b.TxRate
		case sortByTotal:
			less = (a.RxTotal + a.TxTotal) < (b.RxTotal + b.TxTotal)
		case sortByName:
			less = strings.ToLower(a.Comm) < strings.ToLower(b.Comm)
		case sortByPID:
			less = a.PID < b.PID
		case sortByConn:
			less = a.ConnCount < b.ConnCount
		default: // sortByRx
			less = a.RxRate < b.RxRate
		}
		if asc {
			return less
		}
		return !less
	})
}

func sortConns(conns []collector.ConnInfo) {
	sort.Slice(conns, func(i, j int) bool {
		return (conns[i].RxRate + conns[i].TxRate) > (conns[j].RxRate + conns[j].TxRate)
	})
}

func formatBytes(b float64) string {
	switch {
	case b >= 1_073_741_824:
		return fmt.Sprintf("%.1f GB", b/1_073_741_824)
	case b >= 1_048_576:
		return fmt.Sprintf("%.1f MB", b/1_048_576)
	case b >= 1_024:
		return fmt.Sprintf("%.1f KB", b/1_024)
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// calcPIDColWidth returns max-PID-digit-count + 2, with a minimum of 5.
func calcPIDColWidth(procs []collector.ProcessInfo) int {
	w := 3 // width of the "PID" label itself
	for _, p := range procs {
		if d := digitCount(p.PID); d > w {
			w = d
		}
	}
	return w + 2
}

func digitCount(n uint32) int {
	if n == 0 {
		return 1
	}
	d := 0
	for n > 0 {
		d++
		n /= 10
	}
	return d
}
