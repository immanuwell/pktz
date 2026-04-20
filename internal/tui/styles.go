package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Brand / chrome
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#A78BFA"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4B5563"))

	errorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F87171"))

	// Table header
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#E5E7EB")).
			Underline(true)

	// Table rows
	selectedStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#5B21B6")).
			Foreground(lipgloss.Color("#FFFFFF"))

	normalStyle = lipgloss.NewStyle()

	// Traffic rate colours
	rateHighStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#34D399"))
	rateMidStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D"))
	rateLowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#9CA3AF"))

	// Detail view breadcrumb
	breadcrumbStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#60A5FA"))

	protoTCPStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#34D399"))
	protoUDPStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FBBF24"))

	filterStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9FAFB")).
			Background(lipgloss.Color("#374151")).
			Padding(0, 1)
)

// colourRate picks a style based on magnitude (bytes/sec).
func colourRate(bps float64) lipgloss.Style {
	switch {
	case bps >= 1_000_000:
		return rateHighStyle
	case bps >= 10_000:
		return rateMidStyle
	default:
		return rateLowStyle
	}
}
