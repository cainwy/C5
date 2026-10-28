// Command fig4 measures the local receiver-recovery time across output dimensions
// (Fig. 4): (n,f) in {(3,1),(5,2),(9,4)}, L in {1,2,...,64}, exactly t=f+1 valid
// deliveries supplied, QPC timing, warmup discarded.
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"c5full/internal/c5/m1"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

var (
	qpcProc *syscall.Proc
	qpcFreq float64
)

func qpcInit() {
	k32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return
	}
	p, err := k32.FindProc("QueryPerformanceCounter")
	if err != nil {
		return
	}
	f, err := k32.FindProc("QueryPerformanceFrequency")
	if err != nil {
		return
	}
	var freq int64
	r1, _, _ := f.Call(uintptr(unsafe.Pointer(&freq)))
	if r1 == 0 || freq <= 0 {
		return
	}
	qpcFreq = float64(freq)
	qpcProc = p
}

func qpcNow() int64 {
	if qpcProc == nil {
		return time.Now().UnixNano()
	}
	var c int64
	qpcProc.Call(uintptr(unsafe.Pointer(&c)))
	return c
}

func qpcUS(start, end int64) float64 {
	if qpcProc == nil {
		return float64(end-start) / 1e3
	}
	return float64(end-start) / qpcFreq * 1e6
}

type stat struct {
	Unit   string    `json:"unit"`
	Trials []float64 `json:"trials"`
	Median float64   `json:"median"`
	P95    float64   `json:"p95"`
	Mean   float64   `json:"mean"`
	Min    float64   `json:"min"`
	Max    float64   `json:"max"`
	Reps   int       `json:"reps"`
}

func summarize(unit string, vals []float64) stat {
	if len(vals) == 0 {
		return stat{Unit: unit}
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	idx := int(math.Ceil(0.95*float64(len(s)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	med := s[len(s)/2]
	if len(s)%2 == 0 {
		med = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	return stat{Unit: unit, Trials: vals, Median: med, P95: s[idx], Mean: sum / float64(len(s)),
		Min: s[0], Max: s[len(s)-1], Reps: len(s)}
}

type fig4Point struct {
	N      int  `json:"n"`
	F      int  `json:"f"`
	T      int  `json:"t"`
	L      int  `json:"l"`
	Inputs int  `json:"recovery_inputs"`
	Stat   stat `json:"recovery_ms"`
}

func runFig4(outDir string, reps int) {
	cfgs := [][2]int{{3, 1}, {5, 2}, {9, 4}}
	ls := []int{1, 2, 4, 8, 16, 32, 64}
	var points []fig4Point
	for _, nf := range cfgs {
		n, f := nf[0], nf[1]
		for _, L := range ls {
			tk, err := m1.NewTask(n, f, L, fmt.Sprintf("fig4-n%d-L%d", n, L))
			must(err)
			ds := map[int]*m1.Delivery{}
			for i := 0; i < f+1; i++ {
				ds[i] = tk.MakeDelivery(i)
			}
			for w := 0; w < 3; w++ {
				if r := tk.Recover(cloneDeliveries(ds)); !r.IsOK() {
					panic("fig4: warmup recovery failed")
				}
			}
			var trials []float64
			for r := 0; r < reps; r++ {
				t0 := qpcNow()
				res := tk.Recover(cloneDeliveries(ds))
				dt := qpcUS(t0, qpcNow()) / 1000
				if !res.IsOK() {
					panic("fig4: recovery failed")
				}
				trials = append(trials, dt)
			}
			st := summarize("ms", trials)
			points = append(points, fig4Point{N: n, F: f, T: f + 1, L: L, Inputs: f + 1, Stat: st})
			fmt.Printf("FIG4 n=%d f=%d L=%d reps=%d median_ms=%.6f min=%.6f max=%.6f\n",
				n, f, L, reps, st.Median, st.Min, st.Max)
		}
	}
	b, _ := json.MarshalIndent(map[string]any{
		"schema": "c5-fig4-v1", "generated_utc": time.Now().UTC().Format(time.RFC3339),
		"boundary":        "receiver-local recovery compute only (per-coordinate mask derivation + subtraction + Shamir reconstruction); no proving, no MPC, no chain transaction, no network; QPC timer; 3 warmup reps discarded",
		"recovery_inputs": "exactly t=f+1 deliveries",
		"points":          points,
	}, "", "  ")
	must(os.WriteFile(filepath.Join(outDir, "fig4_receiver_latency.json"), append(b, '\n'), 0o644))
	writeFig4CSV(filepath.Join(outDir, "fig4_receiver_latency.csv"), points)
}

func cloneDeliveries(in map[int]*m1.Delivery) map[int]*m1.Delivery {
	out := make(map[int]*m1.Delivery, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func writeFig4CSV(path string, pts []fig4Point) {
	f, err := os.Create(path)
	must(err)
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	must(w.Write([]string{"n", "f", "t", "l", "recovery_inputs", "unit", "reps",
		"median", "mean", "p95", "min", "max"}))
	for _, p := range pts {
		must(w.Write([]string{strconv.Itoa(p.N), strconv.Itoa(p.F), strconv.Itoa(p.T), strconv.Itoa(p.L),
			strconv.Itoa(p.Inputs), "ms", strconv.Itoa(p.Stat.Reps),
			strconv.FormatFloat(p.Stat.Median, 'f', -1, 64),
			strconv.FormatFloat(p.Stat.Mean, 'f', -1, 64),
			strconv.FormatFloat(p.Stat.P95, 'f', -1, 64),
			strconv.FormatFloat(p.Stat.Min, 'f', -1, 64),
			strconv.FormatFloat(p.Stat.Max, 'f', -1, 64)}))
	}
	fmt.Printf("wrote %s\n", path)
}

func main() {
	qpcInit()
	out := flag.String("out", "./data/fig4", "output directory")
	reps := flag.Int("reps", 30, "measured repetitions per point")
	flag.Parse()
	must(os.MkdirAll(*out, 0o755))
	runFig4(*out, *reps)
	fmt.Printf("FIG4_OK reps=%d out=%s\n", *reps, *out)
}
