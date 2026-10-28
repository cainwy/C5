package stats

import (
	"math"
	"math/rand"
	"sort"
)

type Summary struct {
	N          int      `json:"n"`
	MinNS      int64    `json:"min_ns"`
	MaxNS      int64    `json:"max_ns"`
	MeanNS     float64  `json:"mean_ns"`
	StdNS      float64  `json:"std_ns"`
	P5NS       int64    `json:"p5_ns"`
	P25NS      int64    `json:"p25_ns"`
	MedianNS   int64    `json:"median_ns"`
	P75NS      int64    `json:"p75_ns"`
	P95NS      int64    `json:"p95_ns"`
	IQRNS      int64    `json:"iqr_ns"`
	MedianCI95 [2]int64 `json:"median_ci95_bootstrap_ns"`
}

func Quantile(sorted []int64, q float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := q * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return int64(float64(sorted[lo])*(1-frac) + float64(sorted[hi])*frac)
}

func Summarize(samples []int64) Summary {
	s := Summary{N: len(samples)}
	if len(samples) == 0 {
		return s
	}
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	s.MinNS, s.MaxNS = sorted[0], sorted[len(sorted)-1]
	var sum float64
	for _, v := range sorted {
		sum += float64(v)
	}
	s.MeanNS = sum / float64(len(sorted))
	var varsum float64
	for _, v := range sorted {
		d := float64(v) - s.MeanNS
		varsum += d * d
	}
	if len(sorted) > 1 {
		s.StdNS = math.Sqrt(varsum / float64(len(sorted)-1))
	}
	s.P5NS = Quantile(sorted, 0.05)
	s.P25NS = Quantile(sorted, 0.25)
	s.MedianNS = Quantile(sorted, 0.50)
	s.P75NS = Quantile(sorted, 0.75)
	s.P95NS = Quantile(sorted, 0.95)
	s.IQRNS = s.P75NS - s.P25NS
	s.MedianCI95 = BootstrapMedianCI(sorted, 2000, 0xB0C5)
	return s
}

func BootstrapMedianCI(sorted []int64, iters int, seed int64) [2]int64 {
	if len(sorted) == 0 {
		return [2]int64{0, 0}
	}
	rng := rand.New(rand.NewSource(seed))
	meds := make([]int64, iters)
	n := len(sorted)
	buf := make([]int64, n)
	for it := 0; it < iters; it++ {
		for i := 0; i < n; i++ {
			buf[i] = sorted[rng.Intn(n)]
		}
		sort.Slice(buf, func(a, b int) bool { return buf[a] < buf[b] })
		meds[it] = Quantile(buf, 0.5)
	}
	sort.Slice(meds, func(a, b int) bool { return meds[a] < meds[b] })
	return [2]int64{Quantile(meds, 0.025), Quantile(meds, 0.975)}
}

func MS(ns int64) float64 { return float64(ns) / 1e6 }
