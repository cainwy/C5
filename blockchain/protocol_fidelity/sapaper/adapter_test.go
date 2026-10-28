package sapaper


import (
	"math/big"
	"testing"
)

const testN, testT, testM = 5, 3, 3

func buildTestFixture(t *testing.T) *Fixture {
	t.Helper()
	task, err := NewSAPaperTask(testN, testT, testM, "sapaper-test-v1")
	if err != nil {
		t.Fatalf("NewSAPaperTask: %v", err)
	}
	x := big.NewInt(0x1234567)
	y := big.NewInt(0x89abcde)
	fx, err := task.BuildFixture(x, y, "build")
	if err != nil {
		t.Fatalf("BuildFixture: %v", err)
	}
	return fx
}

func TestSAKeyNotGenerator(t *testing.T) {
	fx := buildTestFixture(t)
	g := fx.Task.Group
	if fx.Task.PubKey.Cmp(g.G) == 0 {
		t.Fatal("PubKey h == generator g (SA-F03 regression: degenerate key s=1)")
	}
	q := g.ScalarMod()
	if new(big.Int).Exp(fx.Task.PubKey, q, g.P).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("PubKey h not in order-q subgroup")
	}
	for _, sm := range fx.Servers {
		if len(sm.ZKPoCs) != fx.Task.EG.W() || len(sm.Cts) != fx.Task.EG.W() {
			t.Fatalf("server %d: w mismatch", sm.Index)
		}
	}
}

func TestSAEq18PositiveAndTamper(t *testing.T) {
	fx := buildTestFixture(t)
	for i := 1; i <= fx.Task.N; i++ {
		ok, err := fx.VerifyServer(i)
		if err != nil {
			t.Fatalf("server %d VerifyServer err: %v", i, err)
		}
		if !ok {
			t.Fatalf("server %d: Eq18 positive case must hold", i)
		}
	}
	fx.TamperServerCiphertext(2, 0)
	ok, err := fx.VerifyServer(2)
	if err != nil {
		t.Fatalf("tampered VerifyServer err: %v", err)
	}
	if ok {
		t.Fatal("Eq18 tampered ciphertext must be rejected (SA-PAPER-EQ18-01)")
	}
	for i := 1; i <= fx.Task.N; i++ {
		if i == 2 {
			continue
		}
		if ok, _ := fx.VerifyServer(i); !ok {
			t.Fatalf("server %d must still verify after unrelated tamper", i)
		}
	}
}

func TestSAMofMRecovery(t *testing.T) {
	fx := buildTestFixture(t)
	idx := []int{1, 2, 3}
	z, err := fx.RecoverOutput(idx)
	if err != nil {
		t.Fatalf("RecoverOutput: %v", err)
	}
	if z.Cmp(fx.Expected) != 0 {
		t.Fatalf("recovered %s != expected x*y %s", z, fx.Expected)
	}
	z2, err := fx.RecoverOutput([]int{3, 5, 4})
	if err != nil {
		t.Fatalf("RecoverOutput subset2: %v", err)
	}
	if z2.Cmp(fx.Expected) != 0 {
		t.Fatalf("subset2 recovered %s != expected", z2)
	}
}

func TestSAIntermediatesVerifiable(t *testing.T) {
	fx := buildTestFixture(t)
	sm := fx.Servers[0]
	bad := *sm.Intermediate
	bad.D = new(big.Int).Add(sm.Intermediate.D, big.NewInt(1))
	bad.D.Mod(bad.D, fx.Task.Group.ScalarMod())
	if _, err := fx.Contract.DeriveMulCommitmentG(&bad, big.NewInt(3), big.NewInt(5)); err == nil {
		t.Fatal("Eq17 must reject wrong d_i")
	}
}

func TestSAByteAccountingFixedWidth(t *testing.T) {
	task, err := NewSATaskProfile(ProfileP, 3, 2, 3, "sapaper-bytes-test-v1")
	if err != nil {
		t.Fatalf("NewSATaskProfile(ProfileP): %v", err)
	}
	x := big.NewInt(0x1234567)
	y := big.NewInt(0x89abcde)
	fx, err := task.BuildFixture(x, y, "build")
	if err != nil {
		t.Fatalf("BuildFixture: %v", err)
	}
	g := task.Group
	E := g.ElemSizeBytes()
	S := g.ScalarSizeBytes()
	w := task.EG.W()
	if E != 32 || S != 32 {
		t.Fatalf("ProfileP fixed widths: want elem=32/scalar=32, got elem=%d scalar=%d", E, S)
	}
	for i := 1; i <= task.N; i++ {
		ctB, poKB := fx.VerifyServerBytes(i)
		if want := w * 2 * E; ctB != want {
			t.Fatalf("server %d ctBytes=%d, want w×2E=%d", i, ctB, want)
		}
		if want := w * (2*E + 2*S); poKB != want {
			t.Fatalf("server %d poKBytes=%d, want w×(2E+2S)=%d", i, poKB, want)
		}
	}
	idx := []int{1, 2}
	want := len(idx) * w * (2*E + task.M*E + 4)
	if got := fx.RecoverBytes(idx); got != want {
		t.Fatalf("RecoverBytes=%d, want |idx|×w×(2E+m×E+4)=%d", got, want)
	}
}
