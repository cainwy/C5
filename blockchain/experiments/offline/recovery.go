package offline

import (
	"fmt"

	"c5full/internal/c5/m1"

	"c5full/blockchain/protocol_fidelity/sapaper"
)

type recoveryPoint struct {
	Scheme   string     `json:"scheme"`
	Profile  string     `json:"profile"`
	N        int        `json:"n"`
	F        int        `json:"f"`
	L        int        `json:"l"`
	View     string     `json:"view"`
	MedianMS float64    `json:"total_ms_median"`
	Bytes    int        `json:"bytes,omitempty"`
	ByteBasis string    `json:"byte_basis,omitempty"`
	Stat     StatTrials `json:"trials_stat"`
}

type recoveryGroup struct {
	Profile ProfileInfo `json:"profile"`
	Points  []recoveryPoint `json:"points"`
}

type recoveryResult struct {
	Schema       string          `json:"schema"`
	MeasuredBy   string          `json:"measured_by"`
	GeneratedUTC string          `json:"generated_utc"`
	Profiles     []recoveryGroup `json:"profiles"`
}

// RunRecovery measures only the receiver-recovery view: the computation a single
// receiver performs after t=f+1 deliveries have been publicly verified. Proof
// generation, task registration and chain transactions are excluded.
func RunRecovery(outDir string, reps int, profiles string) {
	if !qpcAvailable() {
		panic("recovery: QPC timer unavailable; sub-millisecond values would be truncated")
	}
	res := &recoveryResult{
		Schema:       "c5-recovery-v1",
		MeasuredBy:   "in-process (pure Go, no Fabric); GOMAXPROCS=4; QPC timer",
		GeneratedUTC: timeNowUTC(),
	}
	for _, pc := range profiles {
		var pk sapaper.ProfileKind
		switch pc {
		case 'M':
			pk = sapaper.ProfileM
		case 'N':
			pk = sapaper.ProfileN
		default:
			continue
		}
		for _, n := range nsX2 {
			f := (n - 1) / 2
			grp := recoveryGroup{}
			grp.Points = append(grp.Points, recoveryC5(n, f, reps)...)
			pts, info := recoverySA(pk, n, f, reps)
			grp.Profile = info
			grp.Points = append(grp.Points, pts...)
			res.Profiles = append(res.Profiles, grp)
			fmt.Printf("RECOVERY profile=%c n=%d done\n", pc, n)
		}
	}
	writeJSON(outDir+"/fig2_recovery.json", res)
}

func recoveryC5(n, f, reps int) []recoveryPoint {
	tk, err := m1.NewTask(n, f, 1, fmt.Sprintf("fig2-c5-n%d", n))
	must(err)
	ds := map[int]*m1.Delivery{}
	for i := 0; i < f+1; i++ {
		ds[i] = tk.MakeDelivery(i)
	}
	trials := make([]float64, 0, reps)
	for r := 0; r < reps; r++ {
		t0 := qpcNow()
		if out := tk.Recover(ds); !out.IsOK() {
			panic("recovery: C5 recovery failed")
		}
		trials = append(trials, msSinceQPC(t0))
	}
	st := newStatMS(trials, false)
	return []recoveryPoint{{
		Scheme: "C5", Profile: "C5", N: n, F: f, L: 1, View: "X2c",
		MedianMS: st.Summary.Median, Stat: st,
		Bytes:     c5PublicVerifyBytes(n, f),
		ByteBasis: "index u32 4B + R 33B + c 32B + delivery sig 64B + Groth16 proof 292B per delivery",
	}}
}

func c5PublicVerifyBytes(n, f int) int {
	const perDelivery = 4 + 33 + 32 + 64 + 292
	return n * perDelivery
}

func recoverySA(pk sapaper.ProfileKind, n, f, reps int) ([]recoveryPoint, ProfileInfo) {
	task, err := sapaper.NewSATaskProfile(pk, n, f+1, 3, fmt.Sprintf("fig2-sa-%s-n%d", metaID(pk), n))
	must(err)
	meta := task.Profile
	info := ProfileInfo{
		ID: meta.ID, Kind: kindName(pk), PrimeBits: meta.PrimeBits, QBits: meta.QBits,
		K: meta.K, ChunkBits: meta.Chunk, W: meta.W, Notes: meta.Notes,
	}
	x := bigNew(0x1234567)
	y := bigNew(0x89abcde)
	fx, err := task.BuildFixture(x, y, "fig2")
	must(err)
	table, err := task.Group.NewBSGSTable(task.EG.ChunkBits)
	must(err)
	idx := make([]int, f+1)
	for i := range idx {
		idx[i] = i + 1
	}
	trials := make([]float64, 0, reps)
	for r := 0; r < reps; r++ {
		t0 := qpcNow()
		z, err := fx.RecoverOutputWithTable(idx, table)
		must(err)
		if z.Cmp(fx.Expected) != 0 {
			panic("recovery: Gai recovery mismatch")
		}
		trials = append(trials, msSinceQPC(t0))
	}
	ctBytes, poKBytes := 0, 0
	for i := 1; i <= n; i++ {
		cb, pb := fx.VerifyServerBytes(i)
		ctBytes += cb
		poKBytes += pb
	}
	st := newStatMS(trials, false)
	return []recoveryPoint{{
		Scheme: meta.ID, Profile: meta.ID, N: n, F: f, L: 1, View: "X2c",
		MedianMS: st.Summary.Median, Stat: st,
		Bytes: ctBytes + poKBytes,
		ByteBasis: fmt.Sprintf("n x w x (ct 2E + ZKPoC 2E+2S), E=%dB, S=%dB",
			task.Group.ElemSizeBytes(), task.Group.ScalarSizeBytes()),
	}}, info
}
