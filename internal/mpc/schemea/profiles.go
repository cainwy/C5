package schemea


import (
	crand "crypto/rand"
	"math/big"
)

type ProfileID string

const (
	PUB256Diag ProfileID = "P-SA-256-DIAG"  // 256-bit, diagnostic only
	PUB1024    ProfileID = "P-SA-1024"
	PUB112     ProfileID = "P-SA-112"       // 2048-bit strengthened (~112-bit)
	PUB128     ProfileID = "P-SA-128"       // 3072-bit main fair point
	PUBLegacy  ProfileID = "P-SA-LEGACY-AMOD"
)

type GroupProfile struct {
	ID         ProfileID
	GroupBits  int // P bit length
	SecurityLabel string
	K, Pchunk, W int
}

func Profiles() []GroupProfile {
	return []GroupProfile{
		{ID: PUB256Diag, GroupBits: 256, SecurityLabel: "diagnostic / paper-route scale point", K: 256, Pchunk: 32, W: 8},
		{ID: PUB1024, GroupBits: 1024, SecurityLabel: "Gai et al. max tested key length (~80-bit)", K: 256, Pchunk: 32, W: 8},
		{ID: PUB112, GroupBits: 2048, SecurityLabel: "~112-bit strengthened (NOT 128)", K: 256, Pchunk: 32, W: 8},
		{ID: PUB128, GroupBits: 3072, SecurityLabel: "main fair security-normalized", K: 256, Pchunk: 32, W: 8},
	}
}

func ProfileIDForBits(bits int) (ProfileID, bool) {
	switch bits {
	case 256:
		return PUB256Diag, true
	case 1024:
		return PUB1024, true
	case 2048:
		return PUB112, true
	case 3072:
		return PUB128, true
	}
	return "", false
}

// 2048-bit: MODP Group 14  (2^2048 - 2^1984 - 1 + 2^64·(⌊2^1918π⌋+124476), g=2)
// 3072-bit: MODP Group 15  (2^3072 - 2^3008 - 1 + 2^64·(⌊2^2942π⌋+1690314), g=2)
var fixedPrimes = map[int]string{
	256: "0x800000000000000000000000000000000000000000000000000000000002FF7F",
	1024: "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
	2048: "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
	3072: "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
}

func NewProfile(pid ProfileID) (*Params, error) {
	profiles := Profiles()
	for _, pf := range profiles {
		if pf.ID == pid {
			pstr, ok := fixedPrimes[pf.GroupBits]
			if !ok {
				return nil, &SchemeAError{"profile prime not embedded"}
			}
			P, ok := new(big.Int).SetString(pstr, 0)
			if !ok {
				return nil, &SchemeAError{"profile prime parse failed"}
			}
			g := big.NewInt(2)
			if !ValidateGroup(P, g) {
				return nil, &SchemeAError{"profile group validation failed"}
			}
			order := new(big.Int).Sub(P, big.NewInt(1))
			s := randExponent(order, crand.Reader)
			h := new(big.Int).Exp(g, s, P)
			p := &Params{P: P, G: g, H: h, S: s, K: pf.K, ChunkBits: pf.Pchunk, NumChunks: pf.K / pf.Pchunk, PrimeBits: P.BitLen()}
			if p.NumChunks != 8 {
				return nil, &SchemeAError{"profile chunk layout wrong"}
			}
			return p, nil
		}
	}
	return nil, &SchemeAError{"unknown profile"}
}

func ValidateGroup(P, g *big.Int) bool {
	if P == nil || !P.ProbablyPrime(40) {
		return false
	}
	if g == nil || g.Cmp(big.NewInt(1)) <= 0 || g.Cmp(P) >= 0 {
		return false
	}
	pm1 := new(big.Int).Sub(P, big.NewInt(1))
	if new(big.Int).Exp(g, pm1, P).Cmp(big.NewInt(1)) != 0 {
		return false
	}
	g2 := new(big.Int).Exp(g, big.NewInt(2), P)
	if g2.Cmp(big.NewInt(1)) == 0 {
		return false
	}
	return true
}

func ProfileParams() (*Params, error) { return NewProfile(PUB128) }