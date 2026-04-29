package tui

import (
	"testing"

	"github.com/immanuwell/pktz/internal/collector"
)

func mkProc(pid uint32, name string, rxRate, txRate float64, rxTotal, txTotal uint64, conns int, rxPPS, txPPS float64, retrans, txPkts uint64) collector.ProcessInfo {
	return collector.ProcessInfo{
		PID:         pid,
		Comm:        name,
		RxRate:      rxRate,
		TxRate:      txRate,
		RxTotal:     rxTotal,
		TxTotal:     txTotal,
		ConnCount:   conns,
		RxPPS:       rxPPS,
		TxPPS:       txPPS,
		RetransPkts: retrans,
		TxPktsTotal: txPkts,
	}
}

func pids(procs []collector.ProcessInfo) []uint32 {
	out := make([]uint32, len(procs))
	for i, p := range procs {
		out[i] = p.PID
	}
	return out
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSortProcs_ByRxRate(t *testing.T) {
	procs := []collector.ProcessInfo{
		mkProc(1, "a", 100, 0, 0, 0, 0, 0, 0, 0, 0),
		mkProc(2, "b", 300, 0, 0, 0, 0, 0, 0, 0, 0),
		mkProc(3, "c", 200, 0, 0, 0, 0, 0, 0, 0, 0),
	}
	sortProcs(procs, sortByRx, false)
	if want := []uint32{2, 3, 1}; !equalU32(pids(procs), want) {
		t.Errorf("desc: got %v, want %v", pids(procs), want)
	}
	sortProcs(procs, sortByRx, true)
	if want := []uint32{1, 3, 2}; !equalU32(pids(procs), want) {
		t.Errorf("asc: got %v, want %v", pids(procs), want)
	}
}

func TestSortProcs_ByTxRate(t *testing.T) {
	procs := []collector.ProcessInfo{
		mkProc(1, "a", 0, 50, 0, 0, 0, 0, 0, 0, 0),
		mkProc(2, "b", 0, 10, 0, 0, 0, 0, 0, 0, 0),
		mkProc(3, "c", 0, 80, 0, 0, 0, 0, 0, 0, 0),
	}
	sortProcs(procs, sortByTx, false)
	if want := []uint32{3, 1, 2}; !equalU32(pids(procs), want) {
		t.Errorf("desc: got %v, want %v", pids(procs), want)
	}
}

func TestSortProcs_ByName(t *testing.T) {
	procs := []collector.ProcessInfo{
		mkProc(1, "Zebra", 0, 0, 0, 0, 0, 0, 0, 0, 0),
		mkProc(2, "apple", 0, 0, 0, 0, 0, 0, 0, 0, 0),
		mkProc(3, "Mango", 0, 0, 0, 0, 0, 0, 0, 0, 0),
	}
	sortProcs(procs, sortByName, true) // ascending is the natural direction for name
	if want := []uint32{2, 3, 1}; !equalU32(pids(procs), want) {
		t.Errorf("asc (case-insensitive): got %v, want %v", pids(procs), want)
	}
}

func TestSortProcs_ByPID(t *testing.T) {
	procs := []collector.ProcessInfo{
		mkProc(30, "c", 0, 0, 0, 0, 0, 0, 0, 0, 0),
		mkProc(10, "a", 0, 0, 0, 0, 0, 0, 0, 0, 0),
		mkProc(20, "b", 0, 0, 0, 0, 0, 0, 0, 0, 0),
	}
	sortProcs(procs, sortByPID, true) // ascending is the natural direction for PID
	if want := []uint32{10, 20, 30}; !equalU32(pids(procs), want) {
		t.Errorf("asc: got %v, want %v", pids(procs), want)
	}
}

func TestSortProcs_ByConn(t *testing.T) {
	procs := []collector.ProcessInfo{
		mkProc(1, "a", 0, 0, 0, 0, 5, 0, 0, 0, 0),
		mkProc(2, "b", 0, 0, 0, 0, 1, 0, 0, 0, 0),
		mkProc(3, "c", 0, 0, 0, 0, 9, 0, 0, 0, 0),
	}
	sortProcs(procs, sortByConn, false)
	if want := []uint32{3, 1, 2}; !equalU32(pids(procs), want) {
		t.Errorf("desc: got %v, want %v", pids(procs), want)
	}
}

func TestSortProcs_ByPPS(t *testing.T) {
	procs := []collector.ProcessInfo{
		mkProc(1, "a", 0, 0, 0, 0, 0, 10, 5, 0, 0),  // pps=15
		mkProc(2, "b", 0, 0, 0, 0, 0, 1, 1, 0, 0),   // pps=2
		mkProc(3, "c", 0, 0, 0, 0, 0, 20, 20, 0, 0), // pps=40
	}
	sortProcs(procs, sortByPPS, false)
	if want := []uint32{3, 1, 2}; !equalU32(pids(procs), want) {
		t.Errorf("desc: got %v, want %v", pids(procs), want)
	}
}

func TestSortProcs_ByRetrans(t *testing.T) {
	procs := []collector.ProcessInfo{
		mkProc(1, "a", 0, 0, 0, 0, 0, 0, 0, 5, 100),  // 5% loss
		mkProc(2, "b", 0, 0, 0, 0, 0, 0, 0, 20, 100), // 20% loss
		mkProc(3, "c", 0, 0, 0, 0, 0, 0, 0, 0, 100),  // 0% loss
	}
	sortProcs(procs, sortByRetrans, false)
	if want := []uint32{2, 1, 3}; !equalU32(pids(procs), want) {
		t.Errorf("desc: got %v, want %v", pids(procs), want)
	}
}

// TestSortProcs_TotalColumns tests sorting triggered by the TOTAL RX (index 4) and
// TOTAL TX (index 5) column headers via procListSortKeys. Test data is constructed
// so that one process dominates in both RxTotal and TxTotal, meaning the expected
// ordering is the same whether the sort key is combined total (pre-PR) or
// per-direction total (post-PR). This lets the test compile and pass both before
// and after PR #2 is merged.
func TestSortProcs_TotalColumns(t *testing.T) {
	if len(procListSortKeys) < 6 {
		t.Fatalf("procListSortKeys too short (%d), expected at least 6", len(procListSortKeys))
	}

	// PID 1 has more RxTotal AND more TxTotal than PID 2, so it comes first
	// regardless of whether the key sorts by combined, Rx-only, or Tx-only.
	dominant := mkProc(1, "heavy", 0, 0, 500, 400, 0, 0, 0, 0, 0)
	lesser := mkProc(2, "light", 0, 0, 100, 50, 0, 0, 0, 0, 0)

	t.Run("TOTAL_RX_column_desc", func(t *testing.T) {
		procs := []collector.ProcessInfo{lesser, dominant}
		sortProcs(procs, procListSortKeys[4], false)
		if procs[0].PID != 1 {
			t.Errorf("TOTAL RX column desc: got first PID %d, want 1", procs[0].PID)
		}
	})

	t.Run("TOTAL_TX_column_desc", func(t *testing.T) {
		procs := []collector.ProcessInfo{lesser, dominant}
		sortProcs(procs, procListSortKeys[5], false)
		if procs[0].PID != 1 {
			t.Errorf("TOTAL TX column desc: got first PID %d, want 1", procs[0].PID)
		}
	})

	t.Run("TOTAL_RX_column_asc", func(t *testing.T) {
		procs := []collector.ProcessInfo{dominant, lesser}
		sortProcs(procs, procListSortKeys[4], true)
		if procs[0].PID != 2 {
			t.Errorf("TOTAL RX column asc: got first PID %d, want 2", procs[0].PID)
		}
	})

	t.Run("TOTAL_TX_column_asc", func(t *testing.T) {
		procs := []collector.ProcessInfo{dominant, lesser}
		sortProcs(procs, procListSortKeys[5], true)
		if procs[0].PID != 2 {
			t.Errorf("TOTAL TX column asc: got first PID %d, want 2", procs[0].PID)
		}
	})
}

// TestProcListLayout verifies that the three parallel slices defining the process
// table (columns widths, headers, sort keys) all have the same length.
func TestProcListLayout(t *testing.T) {
	if len(procListCols) != len(procListHeaders) {
		t.Errorf("procListCols len %d != procListHeaders len %d", len(procListCols), len(procListHeaders))
	}
	if len(procListSortKeys) != len(procListHeaders) {
		t.Errorf("procListSortKeys len %d != procListHeaders len %d", len(procListSortKeys), len(procListHeaders))
	}
}
