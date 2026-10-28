// Command selftest checks the functional claims of the evaluation section:
// deliveries with tampered ciphertexts, proofs or signatures must be rejected,
// recovery must fail below t=f+1 shares, and every valid subset above the
// threshold must reconstruct the same output.
// Output: v4_x6_adversarial_matrix.json in -out.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"c5full/blockchain/experiments/offline"
)

func main() {
	out := flag.String("out", "./data/selftest", "output directory")
	reps := flag.Int("reps", 30, "repetitions per rejection case")
	flag.Parse()

	runtime.GOMAXPROCS(4)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "selftest:", err)
		os.Exit(1)
	}
	offline.RunX6(*out, *reps)
	fmt.Printf("SELFTEST_OK reps=%d out=%s\n", *reps, *out)
}
