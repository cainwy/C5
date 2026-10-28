package harness

import (
	"crypto/sha256"
	"io"
)

type HashSeedReader struct {
	seed  []byte
	block uint64
	buf   []byte
	off   int
}

var _ io.Reader = (*HashSeedReader)(nil)

func NewHashSeedReader(seed string) *HashSeedReader {
	return &HashSeedReader{seed: []byte(seed)}
}

func (r *HashSeedReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.off >= len(r.buf) {
			h := sha256.New()
			h.Write(r.seed)
			var idx [8]byte
			for i := 0; i < 8; i++ {
				idx[i] = byte(r.block >> (8 * (7 - i)))
			}
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