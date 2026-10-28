package schemeafaithful


import (
	"io"
	"math/big"
	"sort"
	"time"
)

type Fig567Config struct {
	Ns       []int
	Rhos     []float64
	KeyLens  []int
	Reps     int
	CalReps  int
	PrimeBits int
	ElGamal  ElGamalConfig
}

func DefaultFig567() Fig567Config {
	return Fig567Config{
		Ns:       nsRange(3, 30),
		Rhos:     []float64{0.3, 0.4, 0.5, 0.6, 0.7},
		KeyLens:  []int{64, 128, 256},
		Reps:     3,
		CalReps:  20,
		PrimeBits: 256,
		ElGamal:  DefaultElGamal,
	}
}

func nsRange(lo, hi int) []int {
	out := make([]int, 0, hi-lo+1)
	for n := lo; n <= hi; n++ {
		out = append(out, n)
	}
	return out
}

type CalibratedOps struct {
	TspMs float64
	TssMs float64
	TseMs float64
	TcgMs float64
	TedMs float64
	TsrMs float64
	PrimeBits int
	Reps  int
}

func CalibrateOps(cfg Fig567Config, r io.Reader) (*CalibratedOps, error) {
	grp, err := NewGroupRandom(cfg.PrimeBits, 42)
	if err != nil {
		return nil, err
	}
	hKP, err := grp.NewKeyPair(randReader{r})
	if err != nil {
		return nil, err
	}
	mod := grp.ScalarMod()
	nCal := 10
	tCal := 3
	sp := []float64{}
	ss := []float64{}
	se := []float64{}
	cg := []float64{}
	ed := []float64{}
	sr := []float64{}
	for i := 0; i < cfg.CalReps; i++ {
		t0 := time.Now()
		if _, err := NewChannelKey(256, r); err != nil {
			return nil, err
		}
		sp = append(sp, msOf(time.Since(t0)))
		secret, _ := RandScalar(mod, r)
		rho, _ := RandScalar(mod, r)
		t1 := time.Now()
		set, err := grp.VSSShare(secret, rho, hKP.H, tCal, nCal, r)
		if err != nil {
			return nil, err
		}
		for _, sh := range set.Shares {
			if _, err := grp.VerifyShare(hKP.H, set.E, sh); err != nil {
				return nil, err
			}
		}
		ss = append(ss, msOf(time.Since(t1))/float64(nCal))
		key, err := NewChannelKey(256, r)
		if err != nil {
			return nil, err
		}
		t2 := time.Now()
		sealed, err := key.Seal(set.Shares[0].S.Bytes())
		if err != nil {
			return nil, err
		}
		if _, err := key.Open(sealed); err != nil {
			return nil, err
		}
		se = append(se, msOf(time.Since(t2)))
		v, _ := RandScalar(mod, r)
		bb, _ := RandScalar(mod, r)
		t3 := time.Now()
		grp.Commit(hKP.H, v, bb)
		cg = append(cg, msOf(time.Since(t3)))
		t4 := time.Now()
		d := new(big.Int).Sub(v, bb)
		d.Mod(d, mod)
		ed = append(ed, msOf(time.Since(t4)))
		t5 := time.Now()
		if _, err := Reconstruct(set.Shares[:tCal], mod); err != nil {
			return nil, err
		}
		sr = append(sr, msOf(time.Since(t5)))
	}
	return &CalibratedOps{
		TspMs: median(sp), TssMs: median(ss), TseMs: median(se),
		TcgMs: median(cg), TedMs: median(ed), TsrMs: median(sr),
		PrimeBits: cfg.PrimeBits, Reps: cfg.CalReps,
	}, nil
}

type ModelPoint struct {
	N     int     `json:"n"`
	T     int     `json:"t"`
	Rho   float64 `json:"rho"`
	TcMs  float64 `json:"tc_ms"`
	LcBytes int   `json:"lc_bytes"`
}

func thresholdFor(n int, rho float64) int {
	t := int(rho*float64(n) + 0.5)
	if t < 1 {
		t = 1
	}
	if t > n {
		t = n
	}
	return t
}

func RunFig5Model(cfg Fig567Config, cal *CalibratedOps) []ModelPoint {
	w := cfg.ElGamal.W()
	out := make([]ModelPoint, 0, len(cfg.Ns)*len(cfg.Rhos))
	for _, n := range cfg.Ns {
		for _, rho := range cfg.Rhos {
			t := thresholdFor(n, rho)
			tc := 2*cal.TspMs +
				float64(n)*(cal.TssMs+cal.TseMs) +
				float64(t)*(cal.TcgMs+float64(w)*cal.TedMs) +
				cal.TsrMs
			out = append(out, ModelPoint{N: n, T: t, Rho: rho, TcMs: tc})
		}
	}
	return out
}

func RunFig6Model(cfg Fig567Config) []ModelPoint {
	ca := ComputeCommAccounting(1, 10, 3, cfg.ElGamal.W(), cfg.PrimeBits)
	ac, sig, comm, ec, dv := ca.AESCTLen, ca.SigLen, ca.CommLen, ca.ECLen, ca.DVLen
	w := cfg.ElGamal.W()
	out := make([]ModelPoint, 0, len(cfg.Ns)*len(cfg.Rhos))
	for _, n := range cfg.Ns {
		for _, rho := range cfg.Rhos {
			t := thresholdFor(n, rho)
			lc := 2*n*(ac+sig) + t*comm + t*w*(ec+dv)
			out = append(out, ModelPoint{N: n, T: t, Rho: rho, LcBytes: lc})
		}
	}
	return out
}

type E2EPoint struct {
	N         int     `json:"n"`
	T         int     `json:"t"`
	M         int     `json:"m"`
	KeyLen    int     `json:"keylen"`
	Reps      int     `json:"reps"`
	TotalMs   float64 `json:"total_ms"`
	ProcVerMs float64 `json:"process_verify_ms"` // Fig.7b
	DecryptMs float64 `json:"decrypt_ms"`        // Fig.7c
	DistMs    float64 `json:"distribute_ms"`
	Valid     bool    `json:"valid"`
}

func RunFig7E2E(cfg Fig567Config, r io.Reader) ([]E2EPoint, error) {
	out := []E2EPoint{}
	for _, n := range cfg.Ns {
		for _, kl := range cfg.KeyLens {
			grp, err := NewGroupRandom(kl, int64(n*31+kl))
			if err != nil {
				return nil, err
			}
			t := thresholdFor(n, 0.5)
			m := 3
			scalarBits := grp.ScalarMod().BitLen()
			chunk := (scalarBits + 7) / 8
			k := chunk * 8
			egc := ElGamalConfig{K: k, ChunkBits: chunk}
			x, err := RandScalar(grp.ScalarMod(), r)
			if err != nil {
				return nil, err
			}
			y, err := RandScalar(grp.ScalarMod(), r)
			if err != nil {
				return nil, err
			}
			pcfg := PipelineConfig{T: t, N: n, M: m, Mode: TripleModeClient,
				ElGamal: egc, ZK: DefaultZKPoC, Group: grp}
			totals := []float64{}
			pvs := []float64{}
			decs := []float64{}
			dists := []float64{}
			valid := true
			for rep := 0; rep < cfg.Reps; rep++ {
				res, err := RunE2E(pcfg, x, y, r)
				if err != nil {
					return nil, err
				}
				if !res.Valid {
					valid = false
				}
				totals = append(totals, res.StageMs.TotalMs)
				pvs = append(pvs, res.StageMs.ProcessVerify)
				decs = append(decs, res.StageMs.DecryptPhase)
				dists = append(dists, res.StageMs.DistributeMs)
			}
			out = append(out, E2EPoint{
				N: n, T: t, M: m, KeyLen: kl, Reps: cfg.Reps,
				TotalMs: median(totals), ProcVerMs: median(pvs),
				DecryptMs: median(decs), DistMs: median(dists), Valid: valid,
			})
		}
	}
	return out, nil
}

func JudgeFig567(fig5, fig6 []ModelPoint, fig7 []E2EPoint) (bool, string) {
	for _, rho := range append([]float64(nil), uniqueRhos(fig5)...) {
		prev := -1.0
		for _, p := range fig5 {
			if p.Rho != rho {
				continue
			}
			if prev >= 0 && p.TcMs < prev*0.995 {
				return false, "fig5 trend broken at rho=" + ftoa(rho)
			}
			prev = p.TcMs
		}
	}
	for _, rho := range append([]float64(nil), uniqueRhos(fig6)...) {
		prev := -1
		for _, p := range fig6 {
			if p.Rho != rho {
				continue
			}
			if prev >= 0 && p.LcBytes <= prev {
				return false, "fig6 trend broken at rho=" + ftoa(rho)
			}
			prev = p.LcBytes
		}
	}
	for _, p := range fig7 {
		if !p.Valid {
			return false, "fig7 invalid e2e at n=" + itoa(p.N)
		}
	}
	return true, "FIG567-TREND-PASS"
}

func uniqueRhos(pts []ModelPoint) []float64 {
	seen := map[float64]bool{}
	out := []float64{}
	for _, p := range pts {
		if !seen[p.Rho] {
			seen[p.Rho] = true
			out = append(out, p.Rho)
		}
	}
	sort.Float64s(out)
	return out
}

func ftoa(f float64) string {
	v := int(f*10 + 0.5)
	if v == 0 {
		return "0"
	}
	intPart := v / 10
	frac := v % 10
	return itoa(intPart) + "." + itoa(frac)
}
