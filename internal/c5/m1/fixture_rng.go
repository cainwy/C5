package m1

// LA-03 deterministic fixture support: a seeded SHA-256 counter stream that is

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// hashSeedReader deterministically expands a seed into an io.Reader using
type hashSeedReader struct {
	seed  []byte
	block uint64
	buf   []byte
	off   int
}

func NewHashSeedReader(seed []byte) io.Reader {
	return &hashSeedReader{seed: seed}
}

func (r *hashSeedReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.off >= len(r.buf) {
			h := sha256.New()
			h.Write(r.seed)
			var idx [8]byte
			binary.BigEndian.PutUint64(idx[:], r.block)
			h.Write(idx[:])
			h.Write([]byte{0xFD}) // domain separator
			r.buf = h.Sum(nil)
			r.off = 0
			r.block++
		}
		c := copy(p[n:], r.buf[r.off:])
		r.off += c
		n += c
	}
	return n, nil
}