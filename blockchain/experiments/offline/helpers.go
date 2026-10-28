// helpers.go holds numeric helpers shared by the offline measurements.
package offline

import (
	"math/big"
	"sort"
)

// mustMed returns the median of vals (input order is preserved).
func mustMed(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func bigNew(v int64) *big.Int { return big.NewInt(v) }

// hexOf renders b as a lowercase hex string.
func hexOfAlpha(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}
