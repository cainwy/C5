// Command fig3 compares the proof organisation reported in Fig. 3: baseline B1
// issues one proof per output coordinate, while B2 keeps a single proof over the
// whole output vector (B2 is our scheme).
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"c5full/blockchain/experiments/offline"
)

func main() {
	out := flag.String("out", "./data/fig3", "output directory")
	spec := flag.String("ls", "1,2,4", "output dimensions to compare")
	proofBytes := flag.Int("proof-bytes", 292, "serialized Groth16 proof size in bytes")
	flag.Parse()

	runtime.GOMAXPROCS(4)
	var ls []int
	for _, tok := range strings.Split(*spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		v, err := strconv.Atoi(tok)
		if err != nil || v < 1 {
			fmt.Fprintf(os.Stderr, "fig3: bad L %q\n", tok)
			os.Exit(2)
		}
		ls = append(ls, v)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "fig3:", err)
		os.Exit(1)
	}
	offline.RunX3(*out, ls, *proofBytes)
	fmt.Printf("FIG3_OK out=%s ls=%v\n", *out, ls)
}
