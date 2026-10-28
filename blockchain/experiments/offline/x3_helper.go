// x3_helper.go builds the deterministic synthetic task used when only the
// circuit shape matters.
package offline

import (
	"c5full/internal/c5/m1"
)

func synthTaskX3(n, f, L int) *m1.Task {
	tk, err := m1.NewTaskWithRNG(n, f, L, "x3synth12345",
		newHashSeed("x3synth12345-"+itoa(n)+"-"+itoa(f)+"-"+itoa(L)))
	if err != nil {
		panic(err)
	}
	return tk
}
