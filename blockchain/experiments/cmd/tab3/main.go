// Command tab3 measures relation-specific Groth16 setup, proving and peak memory
// per output dimension (Table 3).
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"strconv"

	"c5full/blockchain/experiments/offline"
)

func main() {
	out := flag.String("out", "./data/tab3", "output directory")
	spec := flag.String("ls", "1,2,4", "output dimensions to measure")
	reps := flag.Int("reps", 1, "measured repetitions per dimension")
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
			fmt.Fprintf(os.Stderr, "tab3: bad L %q\n", tok)
			os.Exit(2)
		}
		ls = append(ls, v)
	}
	if len(ls) == 0 {
		fmt.Fprintln(os.Stderr, "tab3: empty L list")
		os.Exit(2)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "tab3:", err)
		os.Exit(1)
	}
	offline.RunX5(*out, ls, *reps)
	fmt.Printf("TAB3_OK out=%s ls=%v reps=%d\n", *out, ls, *reps)
}
