package schemea

import (
	"encoding/binary"
	"math/big"
)

func encInt(x *big.Int) []byte {
	if x == nil {
		return []byte{0}
	}
	return x.Bytes()
}

func lenPrefixed(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

func (p *Params) CiphertextBytes(ct *Ciphertext) []byte {
	out := append([]byte{}, lenPrefixed(encInt(ct.C0))...)
	out = append(out, lenPrefixed(encInt(ct.C1))...)
	return out
}

func (p *Params) ZKPoCBytes(pf *ZKPoC) []byte {
	out := []byte{}
	for _, x := range []*big.Int{pf.C0, pf.C1, pf.A0, pf.A1, pf.H, pf.D, pf.F} {
		out = append(out, lenPrefixed(encInt(x))...)
	}
	return out
}

func SerializePartial(partial *big.Int, P *big.Int) []byte {
	out := append([]byte{}, lenPrefixed(encInt(partial))...)
	return out
}

func PartialBytesWithIndex(partial *big.Int, clientIndex1Based int, P *big.Int) []byte {
	body := SerializePartial(partial, P)
	out := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(out, uint32(clientIndex1Based))
	copy(out[4:], body)
	return out
}