// Command fig5 derives the authenticated recovery-delivery volume as a function
// of the output dimension L (Fig. 5).
package main

import (
	"flag"
	"fmt"
	"os"

	"c5full/blockchain/experiments/offline"
)

func main() {
	out := flag.String("out", "./data/fig5", "output directory")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "fig5:", err)
		os.Exit(1)
	}
	offline.RunX4(*out)
	fmt.Printf("FIG5_OK out=%s\n", *out)
}
