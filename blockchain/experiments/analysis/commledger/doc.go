// Package commledger derives the dynamic communication volumes of Table 2 from
// the message format, without relying on packet captures.
package commledger

import (
	"fmt"
	"sort"
)

const ScenarioSingleRecoveryCoordinator = "single-recovery-coordinator accounting scenario"

type Doc struct {
	Schema       string       `json:"schema"`
	Source       string       `json:"source"`
	Provenance   string       `json:"provenance"`
	Scenario     string       `json:"scenario"`
	HonestyNotes []string     `json:"honesty_notes"`
	Constants    Constants    `json:"c5_constants"`
	Fields       []Field      `json:"fields"`
	Summary      []SummaryRow `json:"summary"`
}

type Constants struct {
	IndexBytes int    `json:"index_bytes"`
	RBytes     int    `json:"r_bytes"`
	CtBytes    int    `json:"ct_bytes"`
	SigBytes   int    `json:"sig_bytes"`
	ProofBytes int    `json:"proof_bytes"`
	Basis      string `json:"basis"`
}

type SummaryRow struct {
	Scheme          string `json:"scheme"`
	ProfileID       string `json:"profile_id,omitempty"`
	N               int    `json:"n"`
	T               int    `json:"t"`
	M               int    `json:"m"`
	L               int    `json:"l"`
	PVDynBytes      int    `json:"pv_dyn_bytes"`
	RecRecvMinBytes int    `json:"rec_recv_min_bytes"`
	CombinedABytes  int    `json:"combined_a_bytes"`
	CombinedBBytes  int    `json:"combined_b_bytes"`
	Provenance      string `json:"provenance"`
}

func relabel(fs []Field, view string) []Field {
	out := make([]Field, len(fs))
	for i, f := range fs {
		f.View = view
		out[i] = f
	}
	return out
}

func BuildDoc(profiles []Profile, labels []string, ns []int) Doc {
	if len(profiles) != len(labels) {
		panic("commledger: profiles/labels length mismatch")
	}
	d := Doc{
		Schema:     Schema,
		Source:     "blockchain/experiments/analysis/commledger",
		Provenance: "derived/accounted",
		Scenario:   ScenarioSingleRecoveryCoordinator,
		Constants: Constants{
			IndexBytes: C5IndexBytes, RBytes: C5RBytes, CtBytes: C5CtBytes,
			SigBytes: C5SigBytes, ProofBytes: C5ProofBytes,
			Basis: "index u32=4B; R=SEC1 compressed secp256k1=33B; c=F_q fixed=32B; sig=Ed25519=64B; proof=Groth16 BLS12-381 measured=292B",
		},
		HonestyNotes: []string{
			"Accounting scenario: " + ScenarioSingleRecoveryCoordinator + ". One recovery coordinator is compared across schemes (our designated receiver; Gai's coordinator collecting the m partial decryptions). This is not the full native topology of Gai et al., whose cooperative decryption is fully connected.",
			"Volumes are derived/accounted: field width times occurrence count. Frame headers, length prefixes and domain tags are excluded; values are not packet captures.",
			"Public verification counts the dynamic delivery fields a public verifier reads (our scheme: idx, R, c[L], sig, proof; Gai: idx, ciphertext chunks, ZKPoC chunks).",
			"Recovery reception counts what a single recovery coordinator receives: t=f+1 deliveries for our scheme, t server shares plus t*w*m partial decryptions for Gai. Local computation of the coordinator is excluded.",
			"Combined-A unions the two roles when one actor both verifies and recovers; Combined-B sums an independent auditor and an independent recovery coordinator.",
			"m_clients=3 and t=f+1 are counted separately: partial-decryption messages are per client, server shares are per delivery.",
			"Group element width E=ceil(P/8) and subgroup scalar width S=ceil(Q/8) are accounted separately rather than using one 384B width.",
			"Excluded on both sides: registered task state, PK_R, certificates, Groth16 CRS, mask table and registered server set (ours); public parameters, ledger commitments, expected commitment and task metadata (Gai). These are amortized per task.",
			"Caching assumption: proofs and ZKPoC are fetched once per audit session and not re-downloaded by the coordinator; ciphertexts are fetched once. CDN/multicast reuse and per-client on-chain ciphertext retrieval are not modelled.",
			"These views are dynamic payloads only, not total system traffic: static parameters, framing, consensus and ledger overhead are excluded.",
		},
	}
	for _, n := range ns {
		g := NewGeometry(n)
		pv := C5Fields(ViewPVDyn, g)
		rr := C5Fields(ViewRecRecv, g)
		ca := CombinedA(nil, "C5", g)
		cb := CombinedB(nil, "C5", g)
		d.Fields = append(d.Fields, pv...)
		d.Fields = append(d.Fields, rr...)
		d.Fields = append(d.Fields, relabel(ca, ViewCombinedA)...)
		d.Fields = append(d.Fields, relabel(cb, ViewCombinedB)...)
		d.Summary = append(d.Summary, SummaryRow{
			Scheme: "C5", N: n, T: g.T, M: g.M, L: g.L,
			PVDynBytes:      SumFields(pv),
			RecRecvMinBytes: SumFields(rr),
			CombinedABytes:  SumFields(ca),
			CombinedBBytes:  SumFields(cb),
			Provenance:      "derived/accounted",
		})
		for i, p := range profiles {
			lb := labels[i]
			spv := SAFields(p, ViewPVDyn, g, lb)
			srr := SAFields(p, ViewRecRecv, g, lb)
			sca := CombinedA(&p, lb, g)
			scb := CombinedB(&p, lb, g)
			d.Fields = append(d.Fields, spv...)
			d.Fields = append(d.Fields, srr...)
			d.Fields = append(d.Fields, relabel(sca, ViewCombinedA)...)
			d.Fields = append(d.Fields, relabel(scb, ViewCombinedB)...)
			d.Summary = append(d.Summary, SummaryRow{
				Scheme: lb, ProfileID: p.ID, N: n, T: g.T, M: g.M, L: g.L,
				PVDynBytes:      SumFields(spv),
				RecRecvMinBytes: SumFields(srr),
				CombinedABytes:  SumFields(sca),
				CombinedBBytes:  SumFields(scb),
				Provenance:      "derived/accounted",
			})
		}
	}
	sort.SliceStable(d.Summary, func(i, j int) bool {
		if d.Summary[i].Scheme != d.Summary[j].Scheme {
			return d.Summary[i].Scheme < d.Summary[j].Scheme
		}
		return d.Summary[i].N < d.Summary[j].N
	})
	return d
}

func (d Doc) Row(scheme string, n int) (SummaryRow, bool) {
	for _, r := range d.Summary {
		if r.Scheme == scheme && r.N == n {
			return r, true
		}
	}
	return SummaryRow{}, false
}

func (d Doc) String() string { return fmt.Sprintf("commledger(%d fields, %d rows)", len(d.Fields), len(d.Summary)) }
