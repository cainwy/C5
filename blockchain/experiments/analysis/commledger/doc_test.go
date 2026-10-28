package commledger

import "testing"

func TestBuildDocSummaryConsistency(t *testing.T) {
	profiles := []Profile{profileM(), profileN()}
	labels := []string{"Gai (1024)", "Gai (3072)"}
	d := BuildDoc(profiles, labels, []int{3, 5, 9})

	sum := map[string]int{}
	for _, f := range d.Fields {
		sum[f.Scheme+"|"+itoa(f.N)+"|"+f.View] += f.TotalBytes
	}
	for _, s := range d.Summary {
		base := s.Scheme + "|" + itoa(s.N) + "|"
		if got := sum[base+ViewPVDyn]; got != s.PVDynBytes {
			t.Fatalf("%s n=%d public verification fields=%d summary=%d", s.Scheme, s.N, got, s.PVDynBytes)
		}
		if got := sum[base+ViewRecRecv]; got != s.RecRecvMinBytes {
			t.Fatalf("%s n=%d recovery reception fields=%d summary=%d", s.Scheme, s.N, got, s.RecRecvMinBytes)
		}
		if got := sum[base+ViewCombinedA]; got != s.CombinedABytes {
			t.Fatalf("%s n=%d combined-A fields=%d summary=%d", s.Scheme, s.N, got, s.CombinedABytes)
		}
		if got := sum[base+ViewCombinedB]; got != s.CombinedBBytes {
			t.Fatalf("%s n=%d combined-B fields=%d summary=%d", s.Scheme, s.N, got, s.CombinedBBytes)
		}
	}
}

func TestTable2Values(t *testing.T) {
	profiles := []Profile{profileM(), profileN()}
	labels := []string{"Gai (1024)", "Gai (3072)"}
	d := BuildDoc(profiles, labels, []int{3, 5, 9})

	cases := []struct {
		scheme string
		n      int
		pv     int
		recv   int
	}{
		{"C5", 3, 1275, 138},
		{"C5", 5, 2125, 207},
		{"C5", 9, 3825, 345},
		{"Gai (1024)", 3, 13836, 10248},
		{"Gai (3072)", 3, 38412, 30728},
	}
	for _, c := range cases {
		r, ok := d.Row(c.scheme, c.n)
		if !ok {
			t.Fatalf("%s n=%d missing", c.scheme, c.n)
		}
		if r.PVDynBytes != c.pv || r.RecRecvMinBytes != c.recv {
			t.Fatalf("%s n=%d pv=%d recv=%d, want %d/%d",
				c.scheme, c.n, r.PVDynBytes, r.RecRecvMinBytes, c.pv, c.recv)
		}
	}
}

func TestScenarioLabelAndExclusions(t *testing.T) {
	d := BuildDoc([]Profile{profileM()}, []string{"Gai (1024)"}, []int{3})
	if d.Scenario != ScenarioSingleRecoveryCoordinator {
		t.Fatalf("scenario=%q, want %q", d.Scenario, ScenarioSingleRecoveryCoordinator)
	}
	joined := ""
	for _, n := range d.HonestyNotes {
		joined += n + "\n"
	}
	for _, want := range []string{"single-recovery-coordinator", "amortized", "recovery coordinator", "dynamic payloads"} {
		if !contains(joined, want) {
			t.Fatalf("honesty notes missing %q", want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
