package tui

import (
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// blockChars maps eighths (0–8) to Unicode block characters.
var blockChars = []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// renderGraph draws a filled area chart into graphH rows × width columns.
// data contains time-series values, oldest first; it is downsampled to fit width.
// Returns a single string with graphH newline-separated lines.
func renderGraph(data []float64, width, graphH int, clr lipgloss.Color) string {
	if width <= 0 || graphH <= 0 {
		return ""
	}

	cols := fitToWidth(data, width)

	maxVal := 0.0
	for _, v := range cols {
		if v > maxVal {
			maxVal = v
		}
	}

	style := lipgloss.NewStyle().Foreground(clr)
	rows := make([]string, graphH)

	for r := 0; r < graphH; r++ {
		// rowLevel counts from the bottom: 0 = bottom row, graphH-1 = top row.
		rowLevel := graphH - 1 - r
		var sb strings.Builder
		for _, v := range cols {
			var scaled int
			if maxVal > 0 {
				scaled = int(v / maxVal * float64(graphH*8))
				if scaled > graphH*8 {
					scaled = graphH * 8
				}
			}
			fullRows := scaled / 8
			partial := scaled % 8

			var ch rune
			switch {
			case rowLevel < fullRows:
				ch = '█'
			case rowLevel == fullRows && partial > 0:
				ch = blockChars[partial]
			default:
				ch = ' '
			}
			sb.WriteRune(ch)
		}
		rows[r] = style.Render(sb.String())
	}
	return strings.Join(rows, "\n")
}

// renderTimeAxis builds two rows: tick marks ('|') and timestamp labels below them.
// numSamples is the actual number of history entries (500ms each); now is the current time.
func renderTimeAxis(width, numSamples int, now time.Time) string {
	if width <= 0 {
		return "\n"
	}

	const numTicks = 10
	displayedDuration := time.Duration(numSamples) * 500 * time.Millisecond

	tickRow := make([]byte, width)
	for i := range tickRow {
		tickRow[i] = ' '
	}
	labelRow := make([]byte, width)
	for i := range labelRow {
		labelRow[i] = ' '
	}

	lastLabelEnd := -1
	for i := 0; i < numTicks; i++ {
		pos := i * (width - 1) / (numTicks - 1)
		tickRow[pos] = '|'

		var label string
		if displayedDuration > 0 {
			frac := float64(width-1-pos) / float64(width-1)
			age := time.Duration(frac * float64(displayedDuration))
			label = now.Add(-age).Format("15:04:05")
		} else {
			label = now.Format("15:04:05")
		}

		lStart := pos - len(label)/2
		if lStart < 0 {
			lStart = 0
		}
		if lStart+len(label) > width {
			lStart = width - len(label)
		}
		if lStart < 0 || lStart <= lastLabelEnd {
			continue
		}
		end := lStart + len(label)
		if end > width {
			end = width
		}
		copy(labelRow[lStart:end], []byte(label)[:end-lStart])
		lastLabelEnd = end
	}

	style := lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
	return style.Render(string(tickRow)) + "\n" + style.Render(string(labelRow))
}

// fitToWidth maps data onto exactly width columns.
// If len(data) > width: bucket-max downsampling so peaks stay visible.
// If len(data) <= width: right-aligned, left-padded with zeros.
func fitToWidth(data []float64, width int) []float64 {
	n := len(data)
	out := make([]float64, width)
	if n == 0 {
		return out
	}
	if n <= width {
		copy(out[width-n:], data)
		return out
	}
	// Downsample: map each output column to a bucket of input samples.
	for i := 0; i < width; i++ {
		start := i * n / width
		end := (i+1) * n / width
		if end > n {
			end = n
		}
		maxV := 0.0
		for j := start; j < end; j++ {
			if data[j] > maxV {
				maxV = data[j]
			}
		}
		out[i] = maxV
	}
	return out
}
