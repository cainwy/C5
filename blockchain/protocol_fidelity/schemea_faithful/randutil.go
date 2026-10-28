package schemeafaithful

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

type seedReader struct {
	key   []byte
	ctr   uint64
	buf   []byte
}

func randReaderFromSeed(seed int64) *seedReader {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, uint64(seed))
	return &seedReader{key: k}
}

func (r *seedReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			var ctr [8]byte
			binary.BigEndian.PutUint64(ctr[:], r.ctr)
			m := hmac.New(sha256.New, r.key)
			m.Write(ctr[:])
			r.buf = m.Sum(nil)
			r.ctr++
		}
		c := copy(p[n:], r.buf)
		r.buf = r.buf[c:]
		n += c
	}
	return n, nil
}

func randIntFrom(r *seedReader, max *big.Int) *big.Int {
	bits := max.BitLen()
	bytes := (bits + 7) / 8
	for {
		buf := make([]byte, bytes)
		_, _ = r.Read(buf)
		x := new(big.Int).SetBytes(buf)
		if x.Cmp(max) < 0 {
			return x
		}
	}
}
