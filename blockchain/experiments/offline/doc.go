// Package offline implements the off-chain experiments reported in the paper:
// Fig. 1(a), Fig. 2, Fig. 3, Fig. 4, Fig. 5, Table 2 and Table 3. Every function
// runs in-process on the measurement host. Nothing here talks to Fabric; the
// on-chain experiments live in blockchain/experiments/cmd/onchain (Fig. 1(b),
// Table 1 and the end-to-end comparison).
package offline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ProfileInfo describes a Gai et al. parameter set used by Fig. 2 and Table 2.
type ProfileInfo struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	PrimeBits int    `json:"prime_bits"`
	QBits     int    `json:"q_bits"`
	K         int    `json:"k"`
	ChunkBits int    `json:"chunk_bits"`
	W         int    `json:"w"`
	Notes     string `json:"notes"`
}

// WriteJSON marshals v with indentation and writes it to path, creating the
// parent directory when necessary.
func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// WriteJSONL writes one JSON object per line.
func WriteJSONL[T any](path string, rows []T) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func msf(v float64) string { return fmt.Sprintf("%.3f", v) }
