// Package dlogtable implements a bounded-discrete-log lookup table for
// Scheme-A's output recovery (paper eq. (20)-(21): "querying a discrete
// logarithm table").
// Two table forms, both with the SAME semantics as the paper (find v in
// [0, 2^chunkBits) with g^v = target mod P):
//   - FullTable: constructs all 2^chunkBits entries {(g^v mod P) -> v}. This is
//     what the paper's literal wording implies; it is feasible only for
//     small chunkBits (memory = entries x (keyBytes + 4)).
//   - BabyGiantTable: persistent baby-step table of sqrt(2^chunkBits) entries
//     plus giant steps at query time (BSGS with a cached table); feasible for
//     chunkBits=32 (baby table = 2^16 entries), query cost ~2^16 group ops.
// Storage format: on disk, a binary file: [u32 BE chunkBits][u32 BE n] then n
// records of [keyBytes bytes][u32 BE v], where keyBytes = ceil(log2 P / 8) and
// key = g^v mod P left-padded to keyBytes (big-endian). In memory a hash map
// (key string -> v) gives O(1) amortized lookup; the on-disk layout is sorted
// by construction (v ascending), enabling binary-search loading if needed.
package dlogtable

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"time"
)

// FullTable is a complete 2^chunkBits lookup table.
type FullTable struct {
	ChunkBits int
	P         *big.Int // group modulus (dots for key width)
	G         *big.Int
	keyBytes  int
	entries   map[string]uint32
}

// keyOf yields the left-padded big-endian byte key of a group element.
func (t *FullTable) keyOf(x *big.Int) string {
	b := x.Bytes()
	if len(b) < t.keyBytes {
		pad := make([]byte, t.keyBytes-len(b))
		b = append(pad, b...)
	}
	return string(b)
}

// NewFullTable builds all 2^chunkBits entries deterministically (v = 0..2^p-1).
// Returns build time and entry count. Caller must ensure 2^chunkBits is a
// feasible size (see PaperSize analysis in the README section).
func NewFullTable(G, P *big.Int, chunkBits int) (*FullTable, time.Duration, error) {
	n := 1 << uint(chunkBits)
	if n > 1<<22 { // guard: 4M entries * keyBytes ~ 128MB+; refuse silently-large
		return nil, 0, fmt.Errorf("full table of 2^%d entries not feasible (%d)", chunkBits, n)
	}
	keyBytes := (P.BitLen() + 7) / 8
	t := &FullTable{ChunkBits: chunkBits, P: P, G: G, keyBytes: keyBytes,
		entries: make(map[string]uint32, n)}
	t0 := time.Now()
	cur := big.NewInt(1)
	for v := uint32(0); v < uint32(n); v++ {
		t.entries[t.keyOf(cur)] = v
		cur.Mul(cur, G).Mod(cur, P)
	}
	return t, time.Since(t0), nil
}

// Query returns v with g^v = target mod P (ok=false if absent).
func (t *FullTable) Query(target *big.Int) (uint32, bool) {
	v, ok := t.entries[t.keyOf(target)]
	return v, ok
}

// SizeBytes estimates the in-memory footprint (map overhead approximate).
func (t *FullTable) SizeBytes() int64 {
	return int64(len(t.entries)) * int64(t.keyBytes+4+16)
}

// Save writes the binary layout described in the package docs.
func (t *FullTable) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(t.ChunkBits))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(t.entries)))
	if _, err := f.Write(hdr[:]); err != nil {
		return err
	}
	key := make([]byte, t.keyBytes)
	for v := uint32(0); v < uint32(len(t.entries)); v++ {
		// re-derive g^v (deterministic, same order as build) so file keys are v-sorted
		cur := new(big.Int).Exp(t.G, big.NewInt(int64(v)), t.P)
		b := cur.Bytes()
		for i := range key {
			key[i] = 0
		}
		copy(key[t.keyBytes-len(b):], b)
		if _, err := f.Write(key); err != nil {
			return err
		}
		var vb [4]byte
		binary.BigEndian.PutUint32(vb[:], v)
		if _, err := f.Write(vb[:]); err != nil {
			return err
		}
	}
	return nil
}

// Load reads the binary layout back into a query-ready table.
func Load(path string) (*FullTable, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("truncated header")
	}
	chunk := int(binary.BigEndian.Uint32(b[0:4]))
	n := int(binary.BigEndian.Uint32(b[4:8]))
	totalPer := (len(b) - 8) / n // keyBytes + 4
	keyBytes := totalPer - 4
	t := &FullTable{ChunkBits: chunk, keyBytes: keyBytes, entries: make(map[string]uint32, n)}
	off := 8
	for i := 0; i < n; i++ {
		key := string(b[off : off+keyBytes])
		v := binary.BigEndian.Uint32(b[off+keyBytes : off+keyBytes+4])
		t.entries[key] = v
		off += keyBytes + 4
	}
	return t, nil
}

// BabyGiantTable is a persistent baby-step table for chunkBits=32 (2^16
// entries) plus per-query giant steps.
type BabyGiantTable struct {
	ChunkBits int
	P         *big.Int
	G         *big.Int
	m         int
	keyBytes  int
	baby      map[string]uint32
	gMinvM    *big.Int
}

// NewBabyGiant builds the baby table g^0..g^{m-1}, m=ceil(sqrt(2^chunkBits)).
func NewBabyGiant(G, P *big.Int, chunkBits int) (*BabyGiantTable, time.Duration, error) {
	bound := new(big.Int).Lsh(big.NewInt(1), uint(chunkBits))
	m := new(big.Int).Sqrt(bound)
	m.Add(m, big.NewInt(1))
	mInt := int(m.Int64())
	keyBytes := (P.BitLen() + 7) / 8
	t := &BabyGiantTable{ChunkBits: chunkBits, P: P, G: G, m: mInt,
		keyBytes: keyBytes, baby: make(map[string]uint32, mInt)}
	t0 := time.Now()
	cur := big.NewInt(1)
	for i := 0; i < mInt; i++ {
		b := cur.Bytes()
		key := make([]byte, keyBytes)
		copy(key[keyBytes-len(b):], b)
		t.baby[string(key)] = uint32(i)
		cur.Mul(cur, G).Mod(cur, P)
	}
	gm := new(big.Int).Exp(G, m, P)
	t.gMinvM = new(big.Int).ModInverse(gm, P)
	return t, time.Since(t0), nil
}

// Query solves g^v = target mod P via giant steps over the cached baby table.
func (t *BabyGiantTable) Query(target *big.Int) (uint32, bool) {
	gamma := new(big.Int).Set(target)
	key := make([]byte, t.keyBytes)
	for j := 0; j < t.m; j++ {
		b := gamma.Bytes()
		for i := range key {
			key[i] = 0
		}
		copy(key[t.keyBytes-len(b):], b)
		if v, ok := t.baby[string(key)]; ok {
			return uint32(j)*uint32(t.m) + v, true
		}
		gamma.Mul(gamma, t.gMinvM).Mod(gamma, t.P)
	}
	return 0, false
}

// SizeEntries reports the number of stored entries.
func (t *BabyGiantTable) SizeEntries() int { return t.m }