package sapaper

import (
	"crypto/sha256"
	"encoding/binary"
)

type seedReader struct {
	seed  []byte
	block uint64
	buf   []byte
	off   int
}

func newSeedReader(seed string) *seedReader {
	h := sha256.Sum256([]byte(seed))
	return &seedReader{seed: h[:]}
}

func (r *seedReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.off >= len(r.buf) {
			h := sha256.New()
			h.Write(r.seed)
			var idx [8]byte
			binary.BigEndian.PutUint64(idx[:], r.block)
			h.Write(idx[:])
			r.buf = h.Sum(r.buf[:0])
			r.off = 0
			r.block++
		}
		c := copy(p[n:], r.buf[r.off:])
		r.off += c
		n += c
	}
	return n, nil
}
