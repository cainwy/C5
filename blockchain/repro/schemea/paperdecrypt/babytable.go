package paperdecrypt


import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"time"
)

type BabyGiantTable struct {
	P, G      *big.Int
	BoundBits int
	M         int
	GMInv     *big.Int // (G^M)^{-1} mod P
	KeyBytes  int
	baby      map[string]int32

	BuildNS     int64
	Entries     int
	MemoryBytes int64
	OnDiskBytes int64
	LoadNS      int64
}

func NewBabyGiantTable(P, G *big.Int, boundBits int) (*BabyGiantTable, error) {
	if P == nil || G == nil || P.Sign() <= 0 || G.Sign() <= 0 || G.Cmp(P) >= 0 {
		return nil, &Err{"BabyGiantTable: invalid group"}
	}
	if boundBits < 1 || boundBits > 62 {
		return nil, &Err{fmt.Sprintf("BabyGiantTable: boundBits %d out of range [1,62]", boundBits)}
	}
	t := &BabyGiantTable{
		P: new(big.Int).Set(P), G: new(big.Int).Set(G), BoundBits: boundBits,
		M: 1 << (boundBits / 2), KeyBytes: (P.BitLen() + 7) / 8,
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	tStart := time.Now()
	buf := make([]byte, t.KeyBytes)
	key := func(x *big.Int) string { return string(x.FillBytes(buf)) }
	t.baby = make(map[string]int32, t.M)
	cur := big.NewInt(1)
	for i := 0; i < t.M; i++ {
		t.baby[key(cur)] = int32(i)
		cur.Mul(cur, t.G)
		cur.Mod(cur, t.P)
	}
	gm := new(big.Int).Exp(t.G, big.NewInt(int64(t.M)), t.P)
	inv := new(big.Int).ModInverse(gm, t.P)
	if inv == nil {
		return nil, &Err{"BabyGiantTable: G^M not invertible"}
	}
	t.GMInv = inv
	t.BuildNS = time.Since(tStart).Nanoseconds()
	t.Entries = len(t.baby)
	runtime.ReadMemStats(&m1)
	if m1.HeapAlloc > m0.HeapAlloc {
		t.MemoryBytes = int64(m1.HeapAlloc - m0.HeapAlloc)
	}
	return t, nil
}

func (t *BabyGiantTable) Query(target *big.Int) (*big.Int, bool) {
	if t == nil || target == nil || target.Sign() <= 0 || target.Cmp(t.P) >= 0 {
		return nil, false
	}
	buf := make([]byte, t.KeyBytes)
	key := func(x *big.Int) string { return string(x.FillBytes(buf)) }
	gamma := new(big.Int).Set(target)
	for j := 0; j < t.M; j++ {
		if v, ok := t.baby[key(gamma)]; ok {
			res := big.NewInt(int64(j) * int64(t.M))
			return res.Add(res, big.NewInt(int64(v))), true
		}
		gamma.Mul(gamma, t.GMInv)
		gamma.Mod(gamma, t.P)
	}
	return nil, false
}

const babyTableMagic = "C5BGT1\x00"

func (t *BabyGiantTable) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := func(v any) error { return binary.Write(f, binary.BigEndian, v) }
	if _, err := f.Write([]byte(babyTableMagic)); err != nil {
		return err
	}
	pb := t.P.Bytes()
	gb := t.G.Bytes()
	var n int64
	if err := w(uint32(t.BoundBits)); err != nil {
		return err
	}
	if err := w(uint32(t.KeyBytes)); err != nil {
		return err
	}
	if err := w(uint32(len(pb))); err != nil {
		return err
	}
	if _, err := f.Write(pb); err != nil {
		return err
	}
	if err := w(uint32(len(gb))); err != nil {
		return err
	}
	if _, err := f.Write(gb); err != nil {
		return err
	}
	if err := w(uint64(len(t.baby))); err != nil {
		return err
	}
	pad := make([]byte, t.KeyBytes)
	bulk := make([]byte, 0, len(t.baby)*(t.KeyBytes+4))
	for k, v := range t.baby {
		copy(pad, k)
		bulk = append(bulk, pad...)
		var vb [4]byte
		binary.BigEndian.PutUint32(vb[:], uint32(v))
		bulk = append(bulk, vb[:]...)
		n++
	}
	if _, err := f.Write(bulk); err != nil {
		return err
	}
	st, err := f.Stat()
	if err == nil {
		t.OnDiskBytes = st.Size()
	}
	return nil
}

func LoadBabyGiantTable(path string) (*BabyGiantTable, error) {
	tStart := time.Now()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := func(v any) error { return binary.Read(f, binary.BigEndian, v) }
	magic := make([]byte, len(babyTableMagic))
	if _, err := io.ReadFull(f, magic); err != nil {
		return nil, err
	}
	if string(magic) != babyTableMagic {
		return nil, &Err{"BabyGiantTable load: bad magic"}
	}
	var boundBits, keyBytes, pLen, gLen uint32
	var n uint64
	if err := r(&boundBits); err != nil {
		return nil, err
	}
	if err := r(&keyBytes); err != nil {
		return nil, err
	}
	if err := r(&pLen); err != nil {
		return nil, err
	}
	pb := make([]byte, pLen)
	if _, err := io.ReadFull(f, pb); err != nil {
		return nil, err
	}
	if err := r(&gLen); err != nil {
		return nil, err
	}
	gb := make([]byte, gLen)
	if _, err := io.ReadFull(f, gb); err != nil {
		return nil, err
	}
	if err := r(&n); err != nil {
		return nil, err
	}
	t := &BabyGiantTable{
		P: new(big.Int).SetBytes(pb), G: new(big.Int).SetBytes(gb),
		BoundBits: int(boundBits), M: 1 << (int(boundBits) / 2),
		KeyBytes: int(keyBytes), baby: make(map[string]int32, n),
	}
	rec := uint64(t.KeyBytes) + 4
	bulk := make([]byte, n*rec)
	if _, err := io.ReadFull(f, bulk); err != nil {
		return nil, err
	}
	for i := uint64(0); i < n; i++ {
		off := i * rec
		k := bulk[off : off+uint64(t.KeyBytes)]
		v := binary.BigEndian.Uint32(bulk[off+uint64(t.KeyBytes) : off+rec])
		t.baby[string(k)] = int32(v)
	}
	gm := new(big.Int).Exp(t.G, big.NewInt(int64(t.M)), t.P)
	inv := new(big.Int).ModInverse(gm, t.P)
	if inv == nil {
		return nil, &Err{"BabyGiantTable load: G^M not invertible"}
	}
	t.GMInv = inv
	t.Entries = len(t.baby)
	t.LoadNS = time.Since(tStart).Nanoseconds()
	if st, err := os.Stat(path); err == nil {
		t.OnDiskBytes = st.Size()
	}
	return t, nil
}
