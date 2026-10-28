// x4.go implements the authenticated recovery-delivery volume of Fig. 5:
// (n,f) in {(3,1),(5,2),(9,4)} x L in {1..64}, t=f+1 deliveries per point.
package offline

import (
	"path/filepath"

	"c5full/internal/c5/m1"
)

var nsX4 = [][2]int{{3, 1}, {5, 2}, {9, 4}}
var lsX4 = []int{1, 2, 4, 8, 16, 32, 64}

type x4Point struct {
	N             int    `json:"n"`
	F             int    `json:"f"`
	L             int    `json:"l"`
	T             int    `json:"t"`
	DeliveryBytes int    `json:"delivery_bytes"`
	PerDelivery   int    `json:"per_delivery_bytes"`
	IndexBytes    int    `json:"index_bytes"`
	RBytes        int    `json:"r_bytes"`
	CipherBytes   int    `json:"cipher_bytes"`
	SigBytes      int    `json:"signature_bytes"`
	RecoveredOK   bool   `json:"recovered_ok"`
	ByteBasis     string `json:"byte_basis"`
}

type x4Result struct {
	Schema       string    `json:"schema"`
	MeasuredBy   string    `json:"measured_by"`
	GeneratedUTC string    `json:"generated_utc"`
	Points       []x4Point `json:"points"`
}

// RunX4 derives the authenticated recovery-delivery volume. Each delivery the
// receiver must obtain carries a server index, the ephemeral group element, L
// masked-share ciphertext coordinates and the server signature; proofs were
// verified earlier and are not re-transmitted.
func RunX4(outDir string) {
	const (
		indexBytes = 4
		rBytes     = 33
		ctBytes    = 32
		sigBytes   = 64
	)
	res := &x4Result{
		Schema:       "c5-delivery-volume-v1",
		MeasuredBy:   "derived from the delivery message format; the L=1 point is checked against a real recovery",
		GeneratedUTC: timeNowUTC(),
	}
	for _, nf := range nsX4 {
		n, f := nf[0], nf[1]
		bundle, _, _, _, err := m1.ComposeBundleTimed(n, f, bigNew(0x1234567), bigNew(0x89abcde),
			newHashSeed("fig5-bottom"), m1.BottomBundleOpts{})
		must(err)
		cfg := m1.ReceiverConfig{ReceiverX: bigNew(0xE2E0), Authorized: true, MakeSyntheticPoP: true}
		tk, err := m1.NewTaskFromCommittedOutput(bundle, cfg, newHashSeed("fig5-rcv"))
		must(err)
		ds := map[int]*m1.Delivery{}
		for i := 0; i < n; i++ {
			ds[i] = tk.MakeDelivery(i)
		}
		if r := tk.Recover(ds); !r.IsOK() {
			panic("fig5: recovery failed")
		}
		for _, L := range lsX4 {
			cipher := L * ctBytes
			per := indexBytes + rBytes + cipher + sigBytes
			res.Points = append(res.Points, x4Point{
				N: n, F: f, L: L, T: f + 1,
				DeliveryBytes: (f + 1) * per, PerDelivery: per,
				IndexBytes: indexBytes, RBytes: rBytes,
				CipherBytes: cipher, SigBytes: sigBytes,
				RecoveredOK: true,
				ByteBasis:   "t x (index 4B + R 33B + L x 32B masked-share ciphertext + signature 64B); proofs verified earlier are excluded",
			})
		}
	}
	writeJSON(filepath.Join(outDir, "fig5_delivery_volume.json"), res)
}
