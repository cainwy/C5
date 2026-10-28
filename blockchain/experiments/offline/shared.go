// shared.go holds the deterministic seed reader used by the offline measurements.
package offline

import (
	"crypto/sha256"
	"sort"
)

func newHashSeed(seed string) *seedReaderGo { return &seedReaderGo{seed: []byte(seed)} }

type seedReaderGo struct {
	seed  []byte
	block uint64
	buf   []byte
	off   int
}

func (r *seedReaderGo) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.off >= len(r.buf) {
			h := sha256.New()
			h.Write(r.seed)
			var idx [8]byte
			for i := 0; i < 8; i++ {
				idx[i] = byte(r.block >> (8 * (7 - i)))
			}
			h.Write(idx[:])
			r.buf = h.Sum(r.buf[:0])
			r.off = 0
			r.block++
		}
		c := copy(p[n:], r.buf[r.off:])
		r.off += c
		n += c
	}
	return n, nil
}

func medP95(vals []float64) (float64, float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	sort.Float64s(vals)
	n := len(vals)
	med := vals[n/2]
	if n%2 == 0 {
		med = (vals[n/2-1] + vals[n/2]) / 2
	}
	idx := (n*95 + 99) / 100
	if idx >= n {
		idx = n - 1
	}
	return med, vals[idx]
}
