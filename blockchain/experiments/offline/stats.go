// stats.go holds the timing primitives (QPC) and the common statistics block.
package offline


import (
	"math"
	"runtime"
	"sort"
	"syscall"
	"time"
	"unsafe"
)

var (
	qpcProc    = qpcFind()
	qpcFreq    float64
	qpcFailed  bool
	qpcChecked bool
)

func qpcFind() *syscall.Proc {
	if !isWindowsOS() {
		return nil
	}
	k32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return nil
	}
	p, err := k32.FindProc("QueryPerformanceCounter")
	if err != nil {
		return nil
	}
	f32, err := k32.FindProc("QueryPerformanceFrequency")
	if err != nil {
		return nil
	}
	var freq int64
	r1, _, _ := f32.Call(uintptr(unsafe.Pointer(&freq)))
	if r1 == 0 || freq <= 0 {
		return nil
	}
	qpcFreq = float64(freq)
	return p
}

func isWindowsOS() bool {
	return runtime.GOOS == "windows"
}

func qpcNow() int64 {
	if qpcProc == nil {
		qpcFailed = true
		return 0
	}
	var c int64
	r1, _, _ := qpcProc.Call(uintptr(unsafe.Pointer(&c)))
	if r1 == 0 {
		qpcFailed = true
		return 0
	}
	return c
}

func qpcElapsedUS(start, end int64) float64 {
	if qpcFreq == 0 {
		return 0
	}
	return float64(end-start) / qpcFreq * 1e6
}

func qpcAvailable() bool { return !qpcFailed && qpcProc != nil }

type StatSummary struct {
	Median float64 `json:"median"`
	P95    float64 `json:"p95"`
	Mean   float64 `json:"mean"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Reps   int     `json:"reps"`
}

type StatTrials struct {
	Unit       string      `json:"unit"` // us | ms | s | bytes
	Trials     []float64   `json:"trials"`
	Summary    StatSummary `json:"summary"`
	Provenance string      `json:"provenance"` // measured | derived | historical | few-observation
}

func newStatUS(durations []time.Duration, fewObservation bool) StatTrials {
	vals := make([]float64, len(durations))
	for i, d := range durations {
		vals[i] = float64(d.Microseconds())
	}
	prov := "measured"
	if fewObservation {
		prov = "few-observation"
	}
	return finishStat("us", vals, prov)
}

func newStatUSVals(vals []float64, fewObservation bool) StatTrials {
	prov := "measured"
	if fewObservation {
		prov = "few-observation"
	}
	return finishStat("us", vals, prov)
}

func newStatMS(vals []float64, fewObservation bool) StatTrials {
	prov := "measured"
	if fewObservation {
		prov = "few-observation"
	}
	return finishStat("ms", vals, prov)
}

func newStatS(vals []float64, fewObservation bool) StatTrials {
	prov := "measured"
	if fewObservation {
		prov = "few-observation"
	}
	return finishStat("s", vals, prov)
}

func finishStat(unit string, vals []float64, prov string) StatTrials {
	if len(vals) == 0 {
		return StatTrials{Unit: unit, Trials: vals, Summary: StatSummary{}, Provenance: prov}
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	n := float64(len(sorted))
	p95idx := int(math.Ceil(0.95*float64(len(sorted)))) - 1
	if p95idx < 0 {
		p95idx = 0
	}
	if p95idx >= len(sorted) {
		p95idx = len(sorted) - 1
	}
	return StatTrials{
		Unit: unit,
		Trials: vals,
		Summary: StatSummary{
			Median: medianSorted(sorted),
			P95:    sorted[p95idx],
			Mean:   sum / n,
			Min:    sorted[0],
			Max:    sorted[len(sorted)-1],
			Reps:   len(sorted),
		},
		Provenance: prov,
	}
}

func medianSorted(s []float64) float64 {
	n := len(s)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}
