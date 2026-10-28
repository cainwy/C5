package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
)

type MemLedger struct {
	mu sync.Mutex
	m  map[string][]byte
}

func NewMemLedger() *MemLedger { return &MemLedger{m: map[string][]byte{}} }

func (l *MemLedger) GetState(key string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.m[key]
	if !ok {
		return nil, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (l *MemLedger) PutState(key string, value []byte) error {
	if value == nil {
		return fmt.Errorf("harness: nil value")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	v := make([]byte, len(value))
	copy(v, value)
	l.m[key] = v
	return nil
}

func (l *MemLedger) KeysWithPrefix(prefix string) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []string{}
	for k := range l.m {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (l *MemLedger) Snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.m))
	for k, v := range l.m {
		sum := sha256.Sum256(v)
		out = append(out, k+" "+hex.EncodeToString(sum[:]))
	}
	sort.Strings(out)
	return out
}

func (l *MemLedger) SnapshotHash() string {
	h := sha256.New()
	for _, line := range l.Snapshot() {
		h.Write([]byte(line))
		h.Write([]byte{0x0a})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (l *MemLedger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}