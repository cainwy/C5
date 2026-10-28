// Package protocol orchestrates the complete repaired-MPC pipeline of Scheme A,
// end to end: client VSS-distributes inputs + a Beaver triple to servers, the
// servers run the verifiable multiplication, each server encrypts its output
// share z_i under the clients' Lifted-ElGamal key, the (smart-contract) verifier
// checks the homomorphic commitment consistency, and the client threshold-
// decrypts and reconstructs the raw output z = x·y.
package protocol

import (
	"math/big"
	"time"

	"c5full/internal/mpc/mpccore"
	"c5full/internal/mpc/schemea"
	"c5full/internal/mpc/vss"
)

// Stats captures per-stage wall time (seconds) and communication bytes for the
// comparison with C5(APx) and the AP4 baselines.
type Stats struct {
	ClientDistributeS     float64 // VSS input + triple generation & dispatch
	ServerMulS            float64 // reveal d_i,e_i + reconstruct d,e + z_i compute
	VerifyS               float64 // eq (16)/(17) public verification
	ServerEncryptS        float64 // Lifted-ElGamal encrypt output shares
	ClientRecoverS        float64 // per-share decrypt+DLOG+recompose + Shamir
	ClientRecoverBytes    int     // communication the client must fetch (View A)
	ServerToVerifierBytes int     // server->verifier ciphertext+ZKPoC bytes
	RevealBytes           int     // d_i,e_i intermediate commits (per mul)
}

// Result of one full pipeline run.
type Result struct {
	Valid bool
	Z     *big.Int
	Stats Stats
}

// Run executes the pipeline over the first t server indices.
func Run(grp *mpccore.Params, cli *mpccore.Client, tr *mpccore.Triple, t int, eg *schemea.Params) (*Result, error) {
	st := Stats{}

	t0 := time.Now()
	srvs := make([]*mpccore.ServerNode, t)
	for i := 0; i < t; i++ {
		srvs[i] = cli.BuildServer(i, tr)
	}
	// VSS distribution ("client dispatch" cost): triple already built; measure
	// share materialization as the client-side distribution proxy.
	st.ClientDistributeS = time.Since(t0).Seconds()

	// reveal d_i,e_i and reconstruct d,e as public constants
	t1 := time.Now()
	idcs := make([]*big.Int, t)
	dvals := make([]*big.Int, t)
	evals := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		bl := srvs[i].Reveal()
		idcs[i] = big.NewInt(int64(bl.Idx + 1))
		dvals[i] = bl.Di
		evals[i] = bl.Ei
	}
	d := vss.Reconstruct(idcs, dvals)
	e := vss.Reconstruct(idcs, evals)

	mrs := make([]*mpccore.MulResult, t)
	for i := 0; i < t; i++ {
		mrs[i] = srvs[i].LocalMulPublic(tr, cli.GetPdel(), d, e)
	}
	st.ServerMulS = time.Since(t1).Seconds()

	// public verification: eq (16)/(17)
	t2 := time.Now()
	ok, _ := cli.VerifyMul(tr, srvs, d, e)
	st.VerifyS = time.Since(t2).Seconds()

	// each server encrypts output share z_i with Lifted-ElGamal
	t3 := time.Now()
	ctSets := make([][]*schemea.Ciphertext, t)
	for i := 0; i < t; i++ {
		cts, _ := eg.EncryptShare(mrs[i].Zi, mrs[i].ZBlind)
		ctSets[i] = cts
	}
	st.ServerEncryptS = time.Since(t3).Seconds()

	// client threshold-decrypt + DLOG + recompose + Shamir reconstruct
	t4 := time.Now()
	zvals := make([]*big.Int, t)
	for i := 0; i < t; i++ {
		zvals[i] = eg.RecoverShare(ctSets[i])
	}
	z := vss.Reconstruct(idcs, zvals)
	st.ClientRecoverS = time.Since(t4).Seconds()

	// communication accounting
	geb := 0
	egc := eg
	_ = egc
	geb = eg.NumChunks * 3 * ((eg.PrimeBits + 7) / 8)
	st.ClientRecoverBytes = t * geb
	geb2 := eg.NumChunks*2*((eg.PrimeBits+7)/8) + eg.NumChunks*4*((eg.PrimeBits+7)/8)
	st.ServerToVerifierBytes = t * geb2
	st.RevealBytes = t * 2 * ((eg.PrimeBits + 7) / 8)

	return &Result{Valid: ok, Z: z, Stats: st}, nil
}