package tui

import (
	"strings"
	"testing"
	"time"
)

func TestRenderTimeAxisUsesHistorySampleInterval(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	got := renderTimeAxis(100, 10, now)

	rows := strings.Split(got, "\n")
	if len(rows) != 2 || !strings.HasPrefix(rows[1], "11:59:57") {
		t.Fatalf("left edge does not show the 3s history window; got:\n%s", got)
	}
}
