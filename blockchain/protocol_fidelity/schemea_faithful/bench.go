package schemeafaithful

//	Fig.4  : Lifted ElGamal keylen ∈ {64,128,256,512,1024} → result-processing

import (
	"io"
	"math/big"
	"sort"
	"time"
)

type BenchConfig struct {
	KeyLens   []int
	Reps      int
	Seeds     int
	ElGamal   ElGamalConfig
	ZK        ZKPoCConfig
	N, T, M   int
}

func DefaultBench() BenchConfig {
	return BenchConfig{
		KeyLens: []int{64, 128, 256, 512, 1024},
		Reps:    5, Seeds: 3,
		ElGamal: DefaultElGamal, ZK: DefaultZKPoC,
		N: 10, T: 3, M: 5,
	}
}

type KeylenSample struct {
	KeyLenBits      int
	EncryptMsMed    float64
	EncryptMsP95    float64
	VerifyMsMed     float64
	VerifyMsP95     float64
	EncryptPaperMs  float64
	VerifyPaperMs   float64
	PrimeBits       int
}

var Fig4Anchor = map[int][2]float64{
	//   keylen: [encrypt, verify]
	64:   {3.88, 4.79},
	128:  {5.02, 6.20},
	256:  {6.51, 8.12},
	512:  {8.19, 10.31},
	1024: {10.06, 13.17},
}

func RunFig4Scan(cfg BenchConfig, r io.Reader) ([]KeylenSample, error) {
	keylens := cfg.KeyLens
	if len(keylens) == 0 {
		keylens = DefaultBench().KeyLens
	}
	sort.Ints(keylens)
	out := make([]KeylenSample, 0, len(keylens))
	encAll := map[int][]float64{}
	verAll := map[int][]float64{}
	for _, kl := range keylens {
		for seed := 0; seed < cfg.Seeds; seed++ {
			grp, err := NewGroupRandom(kl, int64(seed*7919+kl))
			if err != nil {
				return nil, err
			}
			k := cfg.ElGamal.K
			if grp.ScalarMod().BitLen() < k {
				k = grp.ScalarMod().BitLen()
			}
			egc := ElGamalConfig{K: k, ChunkBits: cfg.ElGamal.ChunkBits}
			hKP, err := grp.NewKeyPair(randReader{r})
			if err != nil {
				return nil, err
			}
			zMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(k)), big.NewInt(1))
			for rep := 0; rep < cfg.Reps; rep++ {
				z, err := randIntMax(randReader{r}, zMax)
				if err != nil {
					return nil, err
				}
				rr, err := RandScalar(grp.ExpMod, randReader{r})
				if err != nil {
					return nil, err
				}
				t0 := time.Now()
				es, err := grp.EncryptShare(hKP.H, z, rr, egc, randReader{r})
				if err != nil {
					return nil, err
				}
				for j, ct := range es.Cts {
					if _, err := grp.MakeZKPoC(hKP.H, ct, es.Vs[j], es.Ls()[j], cfg.ZK, randReader{r}); err != nil {
						return nil, err
					}
				}
				encAll[kl] = append(encAll[kl], ms(time.Since(t0)))
				t1 := time.Now()
				for j, ct := range es.Cts {
					pf, err := grp.MakeZKPoC(hKP.H, ct, es.Vs[j], es.Ls()[j], cfg.ZK, randReader{r})
					if err != nil {
						return nil, err
					}
					ok, err := grp.VerifyZKPoC(hKP.H, ct, pf, cfg.ZK)
					if err != nil || !ok {
						return nil, errf(ErrZKPoC, "bench verify failed (kl=%d)", kl)
					}
				}
				_ = grp.HomomorphicProduct(es.Cts, egc)
				verAll[kl] = append(verAll[kl], ms(time.Since(t1)))
			}
		}
		out = append(out, KeylenSample{
			KeyLenBits:     kl,
			EncryptMsMed:   median(encAll[kl]),
			EncryptMsP95:   p95(encAll[kl]),
			VerifyMsMed:    median(verAll[kl]),
			VerifyMsP95:    p95(verAll[kl]),
			EncryptPaperMs: Fig4Anchor[kl][0],
			VerifyPaperMs:  Fig4Anchor[kl][1],
			PrimeBits:      kl,
		})
	}
	return out, nil
}

func JudgeFig4(samples []KeylenSample) (bool, string) {
	prevE, prevV := -1.0, -1.0
	for _, s := range samples {
		if prevE >= 0 {
			if s.EncryptMsMed < prevE*0.97 || s.VerifyMsMed < prevV*0.97 {
				return false, "trend not monotonically increasing"
			}
		}
		prevE, prevV = s.EncryptMsMed, s.VerifyMsMed
		if s.EncryptPaperMs > 0 && s.EncryptMsMed > 10*s.EncryptPaperMs {
			return false, "encrypt magnitude off >10x (slower) at keylen " + itoa(s.KeyLenBits)
		}
		if s.VerifyPaperMs > 0 && s.VerifyMsMed > 10*s.VerifyPaperMs {
			return false, "verify magnitude off >10x (slower) at keylen " + itoa(s.KeyLenBits)
		}
	}
	return true, "SELF-TEST-PASS (trend monotone + upper-magnitude within 1 order)"
}

type OperationCounts struct {
	M, N, T, W       int
	Rho              float64
	ClientOps        map[string]int
	ServerPerEntity  map[string]int
	ContractOps      map[string]int
	ClientDecryptOps map[string]int
}

func CountOperations(m, n, t, w int) *OperationCounts {
	oc := &OperationCounts{M: m, N: n, T: t, W: w, Rho: float64(t) / float64(n)}
	oc.ClientOps = map[string]int{
		"T_sp_sym_keygen": m,
		"T_ss_share_gen":  n,
		"T_se_share_enc":  n,
		"T_cg_commit_gen": n * t,
		"T_ed_commit_open": 0,
		"T_sr_reconstruct": 1,
	}
	oc.ClientOps["T_cg_commit_gen_per_rho_unit"] = t
	oc.ClientOps["T_ed_blinding_reveal_w"] = w
	oc.ServerPerEntity = map[string]int{
		"share_decrypt": 1, "share_verify": 1,
		"mul_local": 1, "lifted_elgamal_encrypt_w": w, "zkpoc_gen_w": w,
	}
	oc.ContractOps = map[string]int{
		"commitment_derive_n": n, "zkpoc_verify_nw": n * w, "eq18_verify_n": n,
	}
	oc.ClientDecryptOps = map[string]int{
		"partial_decrypt_mw": m * w, "product_combine_w": w,
		"dlog_w": w, "recombine_1": 1, "shamir_reconstruct_1": 1,
	}
	return oc
}

type CommAccounting struct {
	M, N, T, W   int
	PrimeBits    int
	AESCTLen     int // L(AC)
	SigLen       int // L(Sig)
	CommLen      int // L(Comm)
	ECLen        int
	ProofLen     int
	DVLen        int
	ClientBytes  int // 2n(L(AC)+L(Sig)) + tL(Comm) + tw(L(EC)+L(DV))
	ServerBytes  int // 2m(L(AC)+L(Sig)) + mtL(Comm) + w(L(EC)+L(Proof))
	ClientLc     int
}

func ComputeCommAccounting(m, n, t, w, primeBits int) *CommAccounting {
	eb := (primeBits + 7) / 8
	ca := &CommAccounting{
		M: m, N: n, T: t, W: w, PrimeBits: primeBits,
		AESCTLen: 16 + 32,
		SigLen:   64,        // Ed25519
		CommLen:  eb,
		ECLen:    2 * eb,
		ProofLen: 4 * eb,    // ZKPoC: A0,A1,d,f
		DVLen:    eb,
	}
	ca.ClientBytes = 2*n*(ca.AESCTLen+ca.SigLen) + t*ca.CommLen + t*w*(ca.ECLen+ca.DVLen)
	ca.ServerBytes = 2*m*(ca.AESCTLen+ca.SigLen) + m*t*ca.CommLen + w*(ca.ECLen+ca.ProofLen)
	rho := float64(t) / float64(n)
	ca.ClientLc = 2*n*(ca.AESCTLen+ca.SigLen) + int(rho*float64(n))*ca.CommLen +
		int(rho*float64(n))*w*(ca.ECLen+ca.DVLen)
	return ca
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func p95(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	idx := int(0.95 * float64(len(s)))
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func itoa(x int) string {
	if x == 0 {
		return "0"
	}
	neg := x < 0
	if neg {
		x = -x
	}
	var buf [24]byte
	i := len(buf)
	for x > 0 {
		i--
		buf[i] = byte('0' + x%10)
		x /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

type randReader struct{ r io.Reader }

func (rr randReader) Read(p []byte) (int, error) { return rr.r.Read(p) }

func randIntMax(r randReader, max *big.Int) (*big.Int, error) {
	bits := max.BitLen()
	buf := make([]byte, (bits+7)/8)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(buf)
		if x.Cmp(max) < 0 {
			return x, nil
		}
	}
}
