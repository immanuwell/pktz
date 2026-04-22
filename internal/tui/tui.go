// Package tui provides the bubbletea-based terminal UI for pktz.
package tui

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/immanuwell/pktz/internal/collector"
	"github.com/immanuwell/pktz/internal/demo"
	"github.com/immanuwell/pktz/internal/geoip"
	"github.com/immanuwell/pktz/internal/resolver"
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

// procRow is one visible entry in the process list — standalone, group header,
// or an expanded child. The slice is rebuilt whenever m.procs or expansion state changes.
type procRow struct {
	proc       collector.ProcessInfo
	isGroup    bool // group header with children
	isExpanded bool // valid when isGroup=true
	childCount int  // valid when isGroup=true
	isChild    bool // indented child of a group header
	// aggregated stats used when the group is collapsed (header + all children)
	aggRxRate  float64
	aggTxRate  float64
	aggRxTotal uint64
	aggTxTotal uint64
	aggConns   int
}

// tickMsg fires on every refresh interval.
type tickMsg time.Time

// statsMsg carries freshly fetched data from the collector.
type statsMsg struct {
	procs   []collector.ProcessInfo
	conns   []collector.ConnInfo
	history []collector.HistoryEntry
}

// connID is a comparable 5-tuple that uniquely identifies a connection row.
type connID struct {
	srcAddr string
	dstAddr string
	srcPort uint16
	dstPort uint16
	proto   string
}

func makeConnID(c collector.ConnInfo) connID {
	return connID{
		srcAddr: c.SrcAddr.String(),
		dstAddr: c.DstAddr.String(),
		srcPort: c.SrcPort,
		dstPort: c.DstPort,
		proto:   c.Proto,
	}
}

// Model is the root bubbletea model.
type Model struct {
	coll         *collector.Collector
	res          *resolver.Resolver
	activeView   view
	procs        []collector.ProcessInfo
	conns        []collector.ConnInfo
	cursor       int
	pinnedConn   connID // identity of the connection the cursor is on; zero = not pinned
	detailPID    uint32
	detailComm   string
	width        int
	height       int
	sortBy       sortKey
	sortAsc      bool // true = A→Z / low→high, false = Z→A / high→low
	pidColW      int  // dynamic: max PID digits in current list + 2
	mouseEnabled bool // when false the terminal handles mouse natively (text select)
	resolveNames bool // when true show hostname:service, when false show raw ip:port
	compactIPv6  bool // when true shorten IPv6 to first:…:last
	remoteColW   int  // high-watermark width of the REMOTE column; only grows
	geo          *geoip.DB
	showGeo      bool // toggled with 'g'; true when DB is available
	anon         *demo.Anonymizer
	graphPID     uint32
	graphName    string
	history      []collector.HistoryEntry
	filterInput  textinput.Model
	filtering    bool
	appFilter    string // permanent filter set by --app flag; empty = disabled
	procRows     []procRow
	groupExpanded map[uint32]bool // key = parent PID; true = expanded
	err          error
}

// New creates a Model backed by the given collector, resolver, optional GeoIP DB,
// and optional anonymizer (nil when not running in demo mode).
// initialPID, if non-zero, opens the connection detail view for that PID on startup.
// appFilter, if non-empty, permanently filters the process list to matching names.
func New(c *collector.Collector, res *resolver.Resolver, geo *geoip.DB, anon *demo.Anonymizer, initialPID uint32, appFilter string) Model {
	fi := textinput.New()
	fi.Placeholder = "filter…"
	fi.CharLimit = 32

	m := Model{
		coll:          c,
		res:           res,
		sortBy:        sortByName,
		sortAsc:       true,
		pidColW:       5,
		mouseEnabled:  true,
		resolveNames:  true,
		compactIPv6:   true,
		remoteColW:    30,
		geo:           geo,
		showGeo:       geo != nil,
		anon:          anon,
		filterInput:   fi,
		appFilter:     appFilter,
		groupExpanded: make(map[uint32]bool),
	}

	if initialPID != 0 {
		m.activeView = viewConnDetail
		m.detailPID = initialPID
		m.detailComm = readComm(initialPID)
		m.graphPID = initialPID
		m.graphName = m.detailComm
	}

	return m
}

// --- Init ---

func (m Model) Init() tea.Cmd {
	return tea.Batch(fetchStats(m.coll, m.detailPID, m.activeView, m.graphPID, m.anon), tickCmd())
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
		return m, tea.Batch(tickCmd(), fetchStats(m.coll, m.detailPID, m.activeView, m.graphPID, m.anon))

	case statsMsg:
		m.procs = applyFilter(applyAppFilter(msg.procs, m.appFilter), m.filterInput.Value())
		sortProcs(m.procs, m.sortBy, m.sortAsc)
		m.rebuildProcRows()
		m.pidColW = calcPIDColWidth(msg.procs) // use full unfiltered list for width
		m.conns = msg.conns
		sortConns(m.conns)
		m.restorePinnedConn()
		m.history = msg.history
		m.updateRemoteColW()
		if n := listLen(m); m.cursor >= n && n > 0 {
			m.cursor = n - 1
		}
		m.syncGraphPID()

	case tea.MouseMsg:
		if m.mouseEnabled && msg.Action == tea.MouseActionRelease && msg.Button == tea.MouseButtonLeft {
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
			m.syncGraphPID()
			m.pinCursor()
		}

	case "down", "j":
		if max := listLen(m) - 1; m.cursor < max {
			m.cursor++
			m.syncGraphPID()
			m.pinCursor()
		}

	case " ":
		if m.activeView == viewProcessList && m.cursor < len(m.procRows) {
			row := m.procRows[m.cursor]
			if row.isGroup {
				m.groupExpanded[row.proc.PID] = !m.groupExpanded[row.proc.PID]
				m.rebuildProcRows()
				if m.cursor >= len(m.procRows) {
					m.cursor = len(m.procRows) - 1
				}
				m.syncGraphPID()
			}
		}

	case "enter":
		if m.activeView == viewProcessList && len(m.procRows) > 0 {
			p := m.procRows[m.cursor].proc
			m.detailPID = p.PID
			m.detailComm = p.Comm
			m.activeView = viewConnDetail
			m.cursor = 0
			m.pinnedConn = connID{}
			m.remoteColW = 30 // reset watermark for the new process
		}

	case "esc", "backspace":
		if m.activeView == viewConnDetail {
			m.activeView = viewProcessList
			m.cursor = 0
			m.pinnedConn = connID{}
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

	case "r":
		m.resolveNames = !m.resolveNames
		m.updateRemoteColW()

	case "v":
		m.compactIPv6 = !m.compactIPv6
		m.updateRemoteColW()

	case "g":
		if m.geo != nil {
			m.showGeo = !m.showGeo
		}

	case "m":
		if m.mouseEnabled {
			m.mouseEnabled = false
			return m, func() tea.Msg { return tea.DisableMouse() }
		}
		m.mouseEnabled = true
		return m, func() tea.Msg { return tea.EnableMouseCellMotion() }
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

// syncGraphPID keeps graphPID/graphName aligned with the current cursor.
func (m *Model) syncGraphPID() {
	if m.activeView == viewConnDetail {
		m.graphPID = m.detailPID
		m.graphName = m.detailComm
		return
	}
	if len(m.procRows) == 0 {
		return
	}
	cur := m.cursor
	if cur >= len(m.procRows) {
		cur = len(m.procRows) - 1
	}
	m.graphPID = m.procRows[cur].proc.PID
	m.graphName = m.procRows[cur].proc.Comm
}

// pinCursor records the identity of the connection currently under the cursor
// so that restorePinnedConn can find it again after a re-sort.
func (m *Model) pinCursor() {
	if m.activeView == viewConnDetail && m.cursor < len(m.conns) {
		m.pinnedConn = makeConnID(m.conns[m.cursor])
	}
}

// restorePinnedConn moves m.cursor to the row that matches m.pinnedConn after
// the connection list has been re-sorted. If the connection is no longer present
// the cursor is clamped to the end of the list.
func (m *Model) restorePinnedConn() {
	if m.activeView != viewConnDetail || m.pinnedConn == (connID{}) {
		return
	}
	for i, c := range m.conns {
		if makeConnID(c) == m.pinnedConn {
			m.cursor = i
			return
		}
	}
	// Connection disappeared (closed); clamp cursor.
	if m.cursor >= len(m.conns) && len(m.conns) > 0 {
		m.cursor = len(m.conns) - 1
	}
}

// updateRemoteColW measures the widest formatted remote address in the current
// connection list and advances the high-watermark. Call whenever conns or
// display settings change; the column never shrinks so the layout stays stable.
func (m *Model) updateRemoteColW() {
	const minW = 30
	best := minW
	for _, c := range m.conns {
		s := formatAddr(c.DstAddr, c.DstPort, true, m.res, m.resolveNames, m.compactIPv6, m.anon)
		if w := lipgloss.Width(s); w > best {
			best = w
		}
	}
	best += 2 // breathing room between columns
	if best > m.remoteColW {
		m.remoteColW = best
	}
}

// graphPanelHeight returns how many terminal rows the graph panel should occupy.
func (m Model) graphPanelHeight() int {
	h := m.height * 30 / 100
	if h < 8 {
		h = 8
	}
	if h > 14 {
		h = 14
	}
	return h
}

func listLen(m Model) int {
	if m.activeView == viewConnDetail {
		return len(m.conns)
	}
	return len(m.procRows)
}

func fetchStats(c *collector.Collector, pid uint32, v view, graphPID uint32, anon *demo.Anonymizer) tea.Cmd {
	return func() tea.Msg {
		procs := c.Processes()
		if anon != nil {
			procs = anon.Processes(procs)
		}
		var conns []collector.ConnInfo
		if v == viewConnDetail {
			if anon != nil && anon.IsFakePID(pid) {
				conns = anon.FakeConns(pid)
			} else {
				conns = c.Connections(pid)
				if anon != nil {
					conns = anon.Conns(conns)
				}
			}
		}
		return statsMsg{
			procs:   procs,
			conns:   conns,
			history: c.History(graphPID),
		}
	}
}

// --- View ---

func (m Model) View() string {
	if m.err != nil {
		return errorStyle.Render("error: "+m.err.Error()) + "\n"
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		m.renderHeader(),
		m.renderTable(),
		m.renderFooter(),
		m.renderGraphPanel(),
	)
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

	if len(m.procRows) == 0 {
		sb.WriteString(dimStyle.Render("  waiting for network traffic…"))
		sb.WriteString("\n")
		return sb.String()
	}

	// title(1) + blank(1) + col-header(1) + separator(1) + blank(1) + footer(1) + blank(1) + graph panel
	tableRows := m.height - 7 - m.graphPanelHeight()
	if tableRows < 1 {
		tableRows = 1
	}

	start, end := visibleRange(m.cursor, len(m.procRows), tableRows)
	for i := start; i < end; i++ {
		row := m.procRows[i]
		p := row.proc

		// Stats: aggregated for a collapsed group, own stats otherwise.
		rxRate, txRate := p.RxRate, p.TxRate
		rxTotal, txTotal := p.RxTotal, p.TxTotal
		connCount := p.ConnCount
		if row.isGroup && !row.isExpanded {
			rxRate, txRate = row.aggRxRate, row.aggTxRate
			rxTotal, txTotal = row.aggRxTotal, row.aggTxTotal
			connCount = row.aggConns
		}

		// Comm column: optional container badge + group/child indicator.
		var badge string
		if p.ContainerName != "" {
			name := p.ContainerName
			if len(name) > 12 {
				name = name[:11] + "…"
			}
			badge = containerBadgeStyle.Render("["+name+"]") + " "
		}
		badgeW := lipgloss.Width(badge)
		remaining := cols[1] - badgeW
		if remaining < 4 {
			remaining = 4
		}
		var comm string
		switch {
		case row.isGroup && !row.isExpanded:
			suffix := fmt.Sprintf(" +%d", row.childCount)
			comm = badge + "▸ " + truncate(p.Comm, remaining-2-len(suffix)) + suffix
		case row.isGroup && row.isExpanded:
			comm = badge + "▾ " + truncate(p.Comm, remaining-3)
		case row.isChild:
			comm = badge + "  └ " + truncate(p.Comm, remaining-5)
		default:
			comm = badge + truncate(p.Comm, remaining-1)
		}

		rxS := colourRate(rxRate).Render(formatBytes(rxRate) + "/s")
		txS := colourRate(txRate).Render(formatBytes(txRate) + "/s")
		cells := []string{
			fmt.Sprintf("%d", p.PID),
			comm,
			rxS,
			txS,
			formatBytes(float64(rxTotal)),
			formatBytes(float64(txTotal)),
			fmt.Sprintf("%d", connCount),
		}
		style := normalStyle
		prefix := "  "
		if i == m.cursor {
			style = selectedStyle
			prefix = "▶ "
		}
		sb.WriteString(style.Render(prefix + renderCells(cells, cols, style)))
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m Model) renderConnTable() string {
	// Build column list dynamically — GEO column inserted after REMOTE when active.
	cols := []int{22, m.remoteColW, 5, 13, 9, 9, 9, 9}
	headers := []string{"LOCAL", "REMOTE", "PROTO", "STATE", "RX/s", "TX/s", "TOTAL RX", "TOTAL TX"}
	if m.showGeo {
		cols = []int{22, m.remoteColW, 20, 5, 13, 9, 9, 9, 9}
		headers = []string{"LOCAL", "REMOTE", "GEO", "PROTO", "STATE", "RX/s", "TX/s", "TOTAL RX", "TOTAL TX"}
	}

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

	// same overhead as renderProcTable: title(1)+blank(1)+col-header(1)+separator(1)+blank(1)+footer(1)+blank(1)
	tableRows := m.height - 7 - m.graphPanelHeight()
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
			formatAddr(c.SrcAddr, c.SrcPort, false, m.res, m.resolveNames, m.compactIPv6, m.anon),
			formatAddr(c.DstAddr, c.DstPort, true, m.res, m.resolveNames, m.compactIPv6, m.anon),
		}
		if m.showGeo {
			row = append(row, renderGeo(m.geo.Lookup(c.DstAddr)))
		}
		row = append(row,
			protoStyle.Render(c.Proto),
			truncate(c.State, cols[len(row)]-1),
			rxS,
			txS,
			formatBytes(float64(c.RxTotal)),
			formatBytes(float64(c.TxTotal)),
		)

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

// renderGeo formats a geoip.Info into a fixed-width "🇺🇸 GOOGLE" string.
func renderGeo(info geoip.Info) string {
	if info.IsZero() {
		return ""
	}
	if info.Flag == "" {
		return dimStyle.Render(info.Org)
	}
	if info.Org == "" {
		return info.Flag
	}
	return info.Flag + " " + dimStyle.Render(info.Org)
}

// formatAddr formats an IP:port pair for display.
// resolveHost=true triggers reverse-DNS on the IP (used for remote addresses).
// resolve=false bypasses both hostname and service-name resolution (raw mode).
// compactV6=true shortens IPv6 addresses to first:…:last notation.
func formatAddr(ip net.IP, port uint16, resolveHost bool, res *resolver.Resolver, resolve bool, compactV6 bool, anon *demo.Anonymizer) string {
	var host string
	switch {
	case ip == nil:
		host = "?"
	case ip.IsUnspecified():
		host = "*"
	case resolveHost && resolve:
		var found bool
		if anon != nil {
			if h, ok := anon.HostnameFor(ip); ok {
				host = h
				found = true
			}
		}
		if !found {
			host = res.Hostname(ip)
			// If the resolver returned a raw IPv6 (no PTR record), compact it too.
			if compactV6 && len(ip) == 16 && host == ip.String() {
				host = shortIPv6(ip)
			}
		}
	default:
		host = ip.String()
		if compactV6 && len(ip) == 16 {
			host = shortIPv6(ip)
		}
	}

	if port == 0 {
		return host
	}
	if resolve {
		return host + ":" + resolver.ServiceName(port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// shortIPv6 abbreviates a 16-byte IPv6 address to "first:…:last" where first
// and last are the leading and trailing 16-bit groups in lowercase hex.
func shortIPv6(ip net.IP) string {
	first := fmt.Sprintf("%x", uint16(ip[0])<<8|uint16(ip[1]))
	last := fmt.Sprintf("%x", uint16(ip[14])<<8|uint16(ip[15]))
	return first + ":…:" + last
}

func (m Model) renderFooter() string {
	var left string
	if m.filtering {
		left = filterStyle.Render("/") + " " + m.filterInput.View()
	} else if m.activeView == viewProcessList {
		left = dimStyle.Render(fmt.Sprintf("%d process(es)", len(m.procs)))
		if m.appFilter != "" {
			left = filterStyle.Render("app:"+m.appFilter) + "  " + left
		}
	} else {
		left = dimStyle.Render(fmt.Sprintf("%d connection(s)", len(m.conns)))
	}

	var keys string
	mouseHint := "m:disable mouse"
	if !m.mouseEnabled {
		mouseHint = "m:enable mouse"
	}
	resolveHint := "r:raw view"
	if !m.resolveNames {
		resolveHint = "r:resolve names"
	}
	ipv6Hint := "v:full IPv6"
	if !m.compactIPv6 {
		ipv6Hint = "v:compact IPv6"
	}
	if m.activeView == viewProcessList {
		groupHint := ""
		for _, row := range m.procRows {
			if row.isGroup {
				groupHint = "  space:expand"
				break
			}
		}
		keys = helpStyle.Render(fmt.Sprintf("↑↓:nav  enter:detail  click:sort  /:filter  s:sort%s  %s  q:quit", groupHint, mouseHint))
	} else {
		geoHint := ""
		if m.geo != nil {
			if m.showGeo {
				geoHint = "  g:hide geo"
			} else {
				geoHint = "  g:show geo"
			}
		}
		keys = helpStyle.Render(fmt.Sprintf("↑↓:nav  esc:back  %s  %s%s  %s  q:quit", resolveHint, ipv6Hint, geoHint, mouseHint))
	}

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(keys)
	if gap < 1 {
		gap = 1
	}
	return "\n" + left + strings.Repeat(" ", gap) + keys
}

func (m Model) renderGraphPanel() string {
	panelH := m.graphPanelHeight()
	if m.width <= 0 || panelH <= 0 || m.graphPID == 0 {
		return strings.Repeat("\n", panelH)
	}

	chartH := (panelH - 6) / 2
	if chartH < 1 {
		chartH = 1
	}

	var currentRX, currentTX float64
	if len(m.history) > 0 {
		last := m.history[len(m.history)-1]
		currentRX = last.RxRate
		currentTX = last.TxRate
	}

	name := m.graphName
	if name == "" {
		name = fmt.Sprintf("pid %d", m.graphPID)
	}

	titleText := fmt.Sprintf(" ▸ %s  (pid %d)   RX %s/s   TX %s/s   [5 min]",
		name, m.graphPID, formatBytes(currentRX), formatBytes(currentTX))

	separator := dimStyle.Render(strings.Repeat("─", m.width))
	title := graphTitleStyle.Render(titleText)

	var sb strings.Builder
	sb.WriteString(separator + "\n")
	sb.WriteString(title + "\n")

	if len(m.history) == 0 {
		sb.WriteString(dimStyle.Render("  collecting data…"))
		// Pad to the same height as the normal graph path so the table row budget stays stable.
		sb.WriteString(strings.Repeat("\n", panelH-3))
		return sb.String()
	}

	rxData := make([]float64, len(m.history))
	txData := make([]float64, len(m.history))
	for i, h := range m.history {
		rxData[i] = h.RxRate
		txData[i] = h.TxRate
	}

	sb.WriteString(graphRXStyle.Render(" RX") + "\n")
	sb.WriteString(renderGraph(rxData, m.width, chartH, "#34D399") + "\n")
	sb.WriteString(graphTXStyle.Render(" TX") + "\n")
	sb.WriteString(renderGraph(txData, m.width, chartH, "#FCD34D") + "\n")
	sb.WriteString(renderTimeAxis(m.width, len(m.history), time.Now()))
	return sb.String()
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

// rebuildProcRows recomputes m.procRows from m.procs + m.groupExpanded.
// Must be called whenever either changes.
func (m *Model) rebuildProcRows() {
	m.procRows = buildProcRows(m.procs, m.groupExpanded)
}

// minGroupChildren is the minimum number of children a parent needs to be
// shown as a collapsible group rather than individual rows.
const minGroupChildren = 2

func buildProcRows(procs []collector.ProcessInfo, expanded map[uint32]bool) []procRow {
	// Build a set of PIDs present in the current process list.
	inList := make(map[uint32]bool, len(procs))
	for _, p := range procs {
		inList[p.PID] = true
	}

	// Map parent PID → children, but only when the parent is also in the list.
	childrenOf := make(map[uint32][]collector.ProcessInfo)
	for _, p := range procs {
		if inList[p.PPID] {
			childrenOf[p.PPID] = append(childrenOf[p.PPID], p)
		}
	}

	// A process is a group parent only when it has enough children.
	isGroupParent := make(map[uint32]bool)
	for ppid, kids := range childrenOf {
		if len(kids) >= minGroupChildren {
			isGroupParent[ppid] = true
		}
	}

	// Mark which processes are grouped under a parent.
	isGroupedChild := make(map[uint32]bool)
	for ppid := range isGroupParent {
		for _, kid := range childrenOf[ppid] {
			isGroupedChild[kid.PID] = true
		}
	}

	rows := make([]procRow, 0, len(procs))
	for _, p := range procs {
		if isGroupedChild[p.PID] {
			continue // rendered under its parent
		}
		if isGroupParent[p.PID] {
			kids := childrenOf[p.PID]
			exp := expanded[p.PID]
			agg := aggregateGroup(p, kids)
			rows = append(rows, procRow{
				proc:       p,
				isGroup:    true,
				isExpanded: exp,
				childCount: len(kids),
				aggRxRate:  agg.rxRate,
				aggTxRate:  agg.txRate,
				aggRxTotal: agg.rxTotal,
				aggTxTotal: agg.txTotal,
				aggConns:   agg.conns,
			})
			if exp {
				for _, kid := range kids {
					rows = append(rows, procRow{proc: kid, isChild: true})
				}
			}
		} else {
			rows = append(rows, procRow{proc: p})
		}
	}
	return rows
}

type groupAggregate struct {
	rxRate  float64
	txRate  float64
	rxTotal uint64
	txTotal uint64
	conns   int
}

func aggregateGroup(parent collector.ProcessInfo, children []collector.ProcessInfo) groupAggregate {
	agg := groupAggregate{
		rxRate:  parent.RxRate,
		txRate:  parent.TxRate,
		rxTotal: parent.RxTotal,
		txTotal: parent.TxTotal,
		conns:   parent.ConnCount,
	}
	for _, kid := range children {
		agg.rxRate += kid.RxRate
		agg.txRate += kid.TxRate
		agg.rxTotal += kid.RxTotal
		agg.txTotal += kid.TxTotal
		agg.conns += kid.ConnCount
	}
	return agg
}

// applyAppFilter is the permanent filter applied by the --app flag.
// It matches case-insensitively against the process comm name.
func applyAppFilter(procs []collector.ProcessInfo, filter string) []collector.ProcessInfo {
	if filter == "" {
		return procs
	}
	out := procs[:0:0]
	for _, p := range procs {
		if strings.Contains(strings.ToLower(p.Comm), filter) {
			out = append(out, p)
		}
	}
	return out
}

func applyFilter(procs []collector.ProcessInfo, q string) []collector.ProcessInfo {
	if q == "" {
		return procs
	}
	q = strings.ToLower(q)
	out := procs[:0:0]
	for _, p := range procs {
		if strings.Contains(strings.ToLower(p.Comm), q) ||
			strings.Contains(strings.ToLower(p.ContainerName), q) {
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

// readComm reads the process name from /proc/<pid>/comm.
func readComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Sprintf("pid%d", pid)
	}
	return strings.TrimSpace(string(data))
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
