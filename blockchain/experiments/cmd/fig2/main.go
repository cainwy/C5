// Command fig2 measures the receiver-recovery computation of Fig. 2: the work a
// single receiver performs after t=f+1 deliveries are publicly verified, for our
// scheme and for Gai et al.'s 1024-bit and 3072-bit configurations.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"c5full/blockchain/experiments/offline"
)

func main() {
	out := flag.String("out", "./data/fig2", "output directory")
	reps := flag.Int("reps", 5, "measured repetitions per point")
	profiles := flag.String("profiles", "M,N", "Gai configurations: M=1024-bit, N=3072-bit")
	flag.Parse()

	runtime.GOMAXPROCS(4)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "fig2:", err)
		os.Exit(1)
	}
	offline.RunRecovery(*out, *reps, *profiles)
	fmt.Printf("FIG2_OK reps=%d profiles=%s out=%s\n", *reps, *profiles, *out)
}
