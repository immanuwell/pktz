package collector

// maxHistoryLen is the number of 500ms samples kept per process (5 minutes).
const maxHistoryLen = 600

// HistoryEntry is one bandwidth sample.
type HistoryEntry struct {
	RxRate float64 // bytes/sec at this sample
	TxRate float64
}
