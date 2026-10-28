package verify


import (
	"testing"
)

func TestCanonicalConstraintsTable(t *testing.T) {
	cases := []struct {
		L      int
		cons   int
		expect bool
	}{
		{1, 891908, true},
		{2, 1403640, true},
		{4, 2427414, true},
		{1, 1403640, false},
		{2, 891908, false},
		{8, 4475579, false},
		{3, 891908, false},
		{0, 0, false},
	}
	for _, c := range cases {
		if got := CanonicalConstraints(c.L, c.cons); got != c.expect {
			t.Errorf("CanonicalConstraints(L=%d,cons=%d) = %v, want %v", c.L, c.cons, got, c.expect)
		}
	}
}
