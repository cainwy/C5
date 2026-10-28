package commledger

import "testing"

func profileM() Profile {
	return Profile{ID: "Gai(1024)", PrimeBits: 1024, QBits: 256, K: 256, ChunkBits: 32, W: 8}
}

func profileN() Profile {
	return Profile{ID: "Gai(3072)", PrimeBits: 3072, QBits: 256, K: 256, ChunkBits: 32, W: 8}
}

func TestC5PublicVerification(t *testing.T) {
	g := NewGeometry(3)
	per := SumFields(C5Fields(ViewPVDyn, g)) / g.N
	if per != 425 {
		t.Fatalf("per delivery=%d, want 425 (4+33+32+64+292)", per)
	}
	if got := SumFields(C5Fields(ViewPVDyn, g)); got != 1275 {
		t.Fatalf("n=3 total=%d, want 1275", got)
	}
}

func TestC5RecoveryReception(t *testing.T) {
	g := NewGeometry(3)
	if got := SumFields(C5Fields(ViewRecRecv, g)); got != 2*69 {
		t.Fatalf("recovery reception=%d, want 138 (t=2 x 69)", got)
	}
	g5 := NewGeometry(5)
	if got := SumFields(C5Fields(ViewRecRecv, g5)); got != 3*69 {
		t.Fatalf("n=5 recovery reception=%d, want 207", got)
	}
}

func TestSAWidths(t *testing.T) {
	g := NewGeometry(3)
	if got := SumFields(SAFields(profileM(), ViewPVDyn, g, "Gai (1024)")); got != 3*4612 {
		t.Fatalf("Gai 1024 public verification n=3=%d, want %d", got, 3*4612)
	}
	if got := SumFields(SAFields(profileN(), ViewPVDyn, g, "Gai (3072)")); got != 3*12804 {
		t.Fatalf("Gai 3072 public verification n=3=%d, want %d", got, 3*12804)
	}
}

func TestSARecoveryReceptionPartials(t *testing.T) {
	g := NewGeometry(5) // t=3, m=3, w=8
	fs := SAFields(profileM(), ViewRecRecv, g, "Gai (1024)")
	var partial *Field
	for i := range fs {
		if fs[i].Object == "partial decryption (Eq. 20)" {
			partial = &fs[i]
		}
	}
	if partial == nil {
		t.Fatal("partial decryption field missing")
	}
	if want := g.T * 8 * g.M; partial.Count != want {
		t.Fatalf("partial count=%d, want t*w*m=%d", partial.Count, want)
	}
	if partial.UnitBytes != 128 {
		t.Fatalf("partial unit=%d, want E=128 for a 1024-bit modulus", partial.UnitBytes)
	}
}

func TestDeterminism(t *testing.T) {
	g := NewGeometry(9)
	a := SAFields(profileN(), ViewRecRecv, g, "Gai (3072)")
	b := SAFields(profileN(), ViewRecRecv, g, "Gai (3072)")
	if len(a) != len(b) {
		t.Fatalf("field count mismatch %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("field %d differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}
