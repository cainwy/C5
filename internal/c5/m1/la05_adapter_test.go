package m1

import (
	"math/big"
	"testing"

	"c5full/internal/bottomc5"
	"c5full/internal/c5/host"
	"c5full/internal/c5/params"
)

func makeAdapterTask(t *testing.T, x, y *big.Int, rngSeed string) (*Task, *bottomc5.CommittedOutputBundle) {
	t.Helper()
	b, err := ComposeBundle(3, 1, x, y, NewHashSeedReader([]byte(rngSeed)))
	if err != nil {
		t.Fatalf("compose bundle: %v", err)
	}
	cfg := ReceiverConfig{
		ReceiverX: big.NewInt(424242),
		Authorized: true,
		MakeSyntheticPoP: true,
	}
	tk, err := NewTaskFromCommittedOutput(b, cfg, NewHashSeedReader([]byte("rcv-")))
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	return tk, b
}

func TestAdapterHappyPath(t *testing.T) {
	x, y := big.NewInt(123456789), big.NewInt(987654321)
	tk, b := makeAdapterTask(t, x, y, "seed-adapter-1")

	want := new(big.Int).Mul(x, y)
	want.Mod(want, params.Q)
	if got := tk.OutputValues()[0]; got.Cmp(want) != 0 {
		t.Fatalf("output %s != x*y %s", got, want)
	}
	for i := 0; i < tk.N; i++ {
		z, rho := tk.ShareAt(i, 0)
		o, _ := b.OpeningAt(i)
		if z.Cmp(o.Z) != 0 || rho.Cmp(o.Rho) != 0 {
			t.Fatalf("server %d: adapter share != bundle opening", i)
		}
		if !host.PointEqual(tk.ExpectedCommitment(i, 0), host.Pedersen(z, rho)) {
			t.Fatalf("server %d: commitment mismatch", i)
		}
	}
	tk.EndorseAll()
	rec := &DeliveryRecord{CertIndices: []int{0, 1}, CertSigs: [][]byte{tk.Endorsements[0], tk.Endorsements[1]}}
	if r := tk.VerifyCert(rec.CertIndices, rec.CertSigs); !r.IsOK() {
		t.Fatalf("cert fail: %+v", r)
	}
	tk.Finality.Finalize(hexOf(tk.Alpha))
	ds := map[int]*Delivery{0: tk.MakeDelivery(0), 1: tk.MakeDelivery(1)}
	rr := tk.Recover(ds)
	if !rr.IsOK() {
		t.Fatalf("recover fail: %+v", rr)
	}
	recovered := rr.Value.([]*big.Int)
	if recovered[0].Cmp(want) != 0 {
		t.Fatalf("recovered %s != x*y", recovered[0])
	}
}

func TestAdapterRejectsTamperedAout(t *testing.T) {
	x, y := big.NewInt(7), big.NewInt(11)
	b, err := ComposeBundle(3, 1, x, y, NewHashSeedReader([]byte("seed-adapter-tamper")))
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	b.Aout[0][0] = host.AddPoints(b.Aout[0][0], &params.G)
	cfg := ReceiverConfig{ReceiverX: big.NewInt(9), Authorized: true, MakeSyntheticPoP: true}
	if _, err := NewTaskFromCommittedOutput(b, cfg, NewHashSeedReader([]byte("rcv-"))); err == nil {
		t.Fatalf("tampered Aout must fail closed")
	}
}

func TestAdapterRejectsTamperedOpening(t *testing.T) {
	x, y := big.NewInt(3), big.NewInt(5)
	b, err := ComposeBundle(3, 1, x, y, NewHashSeedReader([]byte("seed-adapter-open")))
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	b.Openings[0].Z = incM1(b.Openings[0].Z)
	cfg := ReceiverConfig{ReceiverX: big.NewInt(9), Authorized: true, MakeSyntheticPoP: true}
	if _, err := NewTaskFromCommittedOutput(b, cfg, NewHashSeedReader([]byte("rcv-"))); err == nil {
		t.Fatalf("tampered opening must fail closed")
	}
}

func TestAdapterRejectsDimMismatch(t *testing.T) {
	x, y := big.NewInt(1), big.NewInt(2)
	b, err := ComposeBundle(3, 1, x, y, NewHashSeedReader([]byte("seed-adapter-dim")))
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	b.Aout[0] = append(b.Aout[0], b.Aout[0][0])
	cfg := ReceiverConfig{ReceiverX: big.NewInt(9), Authorized: true, MakeSyntheticPoP: true}
	if _, err := NewTaskFromCommittedOutput(b, cfg, NewHashSeedReader([]byte("rcv-"))); err == nil {
		t.Fatalf("dimension mismatch must fail closed")
	}
}

func TestAdapterRejectsDupXi(t *testing.T) {
	x, y := big.NewInt(1), big.NewInt(2)
	b, err := ComposeBundle(3, 1, x, y, NewHashSeedReader([]byte("seed-adapter-xi")))
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	b.Xi[1] = big.NewInt(1) // duplicate point
	cfg := ReceiverConfig{ReceiverX: big.NewInt(9), Authorized: true, MakeSyntheticPoP: true}
	if _, err := NewTaskFromCommittedOutput(b, cfg, NewHashSeedReader([]byte("rcv-"))); err == nil {
		t.Fatalf("duplicate xi must fail closed")
	}
}