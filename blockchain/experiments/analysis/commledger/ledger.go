package commledger

import "fmt"

const Schema = "c5-dynamic-volume-v1"

const (
	C5IndexBytes = 4
	C5RBytes     = 33
	C5CtBytes    = 32
	C5SigBytes   = 64
	C5ProofBytes = 292
)

const (
	ViewPVDyn     = "PV-DYN"
	ViewRecRecv   = "REC-RECV"
	ViewCombinedA = "COMBINED-A"
	ViewCombinedB = "COMBINED-B"

	ClassOnline = "ONLINE"
)

type Profile struct {
	ID        string `json:"id"`
	PrimeBits int    `json:"prime_bits"`
	QBits     int    `json:"q_bits"`
	K         int    `json:"k"`
	ChunkBits int    `json:"chunk_bits"`
	W         int    `json:"w"`
}

func (p Profile) ElemBytes() int { return (p.PrimeBits + 7) / 8 }

func (p Profile) ScalarBytes() int { return (p.QBits + 7) / 8 }

type Geometry struct {
	N int `json:"n"`
	F int `json:"f"`
	T int `json:"t"`
	M int `json:"m"`
	L int `json:"l"`
}

func NewGeometry(n int) Geometry {
	f := (n - 1) / 2
	return Geometry{N: n, F: f, T: f + 1, M: 3, L: 1}
}

type Field struct {
	Scheme     string `json:"scheme"`
	ProfileID  string `json:"profile_id"`
	View       string `json:"view"`
	N          int    `json:"n"`
	T          int    `json:"t"`
	M          int    `json:"m"`
	L          int    `json:"l"`
	Sender     string `json:"sender"`
	Receiver   string `json:"receiver"`
	Object     string `json:"data_object"`
	Count      int    `json:"count"`
	UnitBytes  int    `json:"unit_bytes"`
	TotalBytes int    `json:"total_bytes"`
	Class      string `json:"class"`
	Reuse      string `json:"reuse"`
	WidthBasis string `json:"width_basis"`
	Provenance string `json:"provenance"`
}

func mkField(scheme, profileID, view string, g Geometry, sender, receiver, obj, reuse, width string, count, unit int) Field {
	return Field{
		Scheme: scheme, ProfileID: profileID, View: view,
		N: g.N, T: g.T, M: g.M, L: g.L,
		Sender: sender, Receiver: receiver, Object: obj,
		Count: count, UnitBytes: unit, TotalBytes: count * unit,
		Class: ClassOnline, Reuse: reuse, WidthBasis: width, Provenance: "derived/accounted",
	}
}

func C5Fields(view string, g Geometry) []Field {
	const scheme = "C5"
	switch view {
	case ViewPVDyn:
		return []Field{
			mkField(scheme, "", view, g, "server_i", "public_verifier", "server index i",
				"per-delivery", "u32", g.N, C5IndexBytes),
			mkField(scheme, "", view, g, "server_i", "public_verifier", "R_i (SEC1 compressed)",
				"per-delivery", "33B constant", g.N, C5RBytes),
			mkField(scheme, "", view, g, "server_i", "public_verifier", "c_{i,1..L} (F_q ciphertext)",
				"per-delivery", "32B x L", g.N*g.L, C5CtBytes),
			mkField(scheme, "", view, g, "server_i", "public_verifier", "delivery signature (Ed25519)",
				"per-delivery", "64B constant", g.N, C5SigBytes),
			mkField(scheme, "", view, g, "server_i", "public_verifier", "Groth16 proof",
				"per-delivery", "292B measured", g.N, C5ProofBytes),
		}
	case ViewRecRecv:
		return []Field{
			mkField(scheme, "", view, g, "server_i", "designated_receiver", "server index i",
				"per-recovery-delivery", "u32", g.T, C5IndexBytes),
			mkField(scheme, "", view, g, "server_i", "designated_receiver", "R_i (SEC1 compressed)",
				"per-recovery-delivery", "33B constant", g.T, C5RBytes),
			mkField(scheme, "", view, g, "server_i", "designated_receiver", "c_{i,1..L} (F_q ciphertext)",
				"per-recovery-delivery", "32B x L", g.T*g.L, C5CtBytes),
		}
	default:
		panic(fmt.Sprintf("C5Fields: unknown view %q", view))
	}
}

func SAFields(p Profile, view string, g Geometry, schemeLabel string) []Field {
	E, S, w := p.ElemBytes(), p.ScalarBytes(), p.W
	switch view {
	case ViewPVDyn:
		return []Field{
			mkField(schemeLabel, p.ID, view, g, "server_i", "public_verifier", "server index i",
				"per-server", "u32", g.N, C5IndexBytes),
			mkField(schemeLabel, p.ID, view, g, "server_i", "public_verifier", "Lifted-ElGamal ciphertext chunks (C0,C1)",
				"per-server x w chunks", "2E, E=ceil(P/8)", g.N*w, 2*E),
			mkField(schemeLabel, p.ID, view, g, "server_i", "public_verifier", "ZKPoC chunks (A0,A1,d,f)",
				"per-server x w chunks", "2E+2S", g.N*w, 2*E+2*S),
		}
	case ViewRecRecv:
		return []Field{
			mkField(schemeLabel, p.ID, view, g, "server_i", "recovering_entity", "server index i",
				"per-recovery-share", "u32", g.T, C5IndexBytes),
			mkField(schemeLabel, p.ID, view, g, "server_i", "recovering_entity", "Lifted-ElGamal ciphertext chunks (C0,C1)",
				"per-recovery-share x w chunks", "2E", g.T*w, 2*E),
			mkField(schemeLabel, p.ID, view, g, "client_c (1..m)", "recovering_entity", "partial decryption (Eq. 20)",
				"t servers x w chunks x m clients", "E", g.T*w*g.M, E),
		}
	default:
		panic(fmt.Sprintf("SAFields: unknown view %q", view))
	}
}

func SumFields(fs []Field) int {
	total := 0
	for _, f := range fs {
		total += f.TotalBytes
	}
	return total
}

func CombinedA(p *Profile, schemeLabel string, g Geometry) []Field {
	if p == nil {
		return C5Fields(ViewPVDyn, g)
	}
	E, w := p.ElemBytes(), p.W
	out := append([]Field{}, SAFields(*p, ViewPVDyn, g, schemeLabel)...)
	out = append(out,
		mkField(schemeLabel, p.ID, ViewCombinedA, g, "client_c (1..m)", "same_actor", "partial decryption (Eq. 20)",
			"t servers x w chunks x m clients (ciphertext already fetched)", "E", g.T*w*g.M, E),
	)
	return out
}

func CombinedB(p *Profile, schemeLabel string, g Geometry) []Field {
	if p == nil {
		out := append([]Field{}, C5Fields(ViewPVDyn, g)...)
		return append(out, C5Fields(ViewRecRecv, g)...)
	}
	out := append([]Field{}, SAFields(*p, ViewPVDyn, g, schemeLabel)...)
	return append(out, SAFields(*p, ViewRecRecv, g, schemeLabel)...)
}
