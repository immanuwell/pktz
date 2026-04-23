package collector

// maxHistoryLen is the number of 300ms samples kept per process (5 minutes).
const maxHistoryLen = 1000

// HistoryEntry is one bandwidth sample.
type HistoryEntry struct {
	RxRate float64 // bytes/sec at this sample
	TxRate float64
	PPS    float64 // combined packets/sec at this sample
}
