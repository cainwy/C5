package offline

import "time"

// writeJSON and ms keep the call sites in the x* measurement files unchanged.
func writeJSON(path string, v any) { must(WriteJSON(path, v)) }

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }
