// Command tab2 builds Table 2 (dynamic communication volumes) from the message
// format of both schemes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"c5full/blockchain/experiments/analysis/commledger"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type rawDoc struct {
	Profiles []struct {
		Profile struct {
			ID        string `json:"id"`
			PrimeBits int    `json:"prime_bits"`
			QBits     int    `json:"q_bits"`
			K         int    `json:"k"`
			ChunkBits int    `json:"chunk_bits"`
			W         int    `json:"w"`
		} `json:"profile"`
	} `json:"profiles"`
}

func labelFor(id string) string {
	switch {
	case strings.Contains(id, "-N-3072"):
		return "Gai (3072)"
	case strings.Contains(id, "-M-1024"):
		return "Gai (1024)"
	default:
		return id
	}
}

func main() {
	src := flag.String("raw", "", "fig2_recovery.json providing the Gai profile parameters")
	out := flag.String("out", "./data/tab2/tab2_communication.json", "output file")
	flag.Parse()

	profiles := []commledger.Profile{}
	labels := []string{}
	seen := map[string]bool{}
	if *src != "" {
		b, err := os.ReadFile(*src)
		must(err)
		var rd rawDoc
		must(json.Unmarshal(b, &rd))
		for _, grp := range rd.Profiles {
			id := grp.Profile.ID
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			profiles = append(profiles, commledger.Profile{
				ID: id, PrimeBits: grp.Profile.PrimeBits, QBits: grp.Profile.QBits,
				K: grp.Profile.K, ChunkBits: grp.Profile.ChunkBits, W: grp.Profile.W,
			})
			labels = append(labels, labelFor(id))
		}
	}
	if len(profiles) == 0 {
		profiles = append(profiles,
			commledger.Profile{ID: "Gai(1024)", PrimeBits: 1024, QBits: 256, K: 256, ChunkBits: 32, W: 8},
			commledger.Profile{ID: "Gai(3072)", PrimeBits: 3072, QBits: 256, K: 256, ChunkBits: 32, W: 8})
		labels = []string{"Gai (1024)", "Gai (3072)"}
	}
	order := map[string]int{"C5": 0, "Gai (1024)": 1, "Gai (3072)": 2}
	sort.SliceStable(profiles, func(a, b int) bool {
		return order[labels[a]] < order[labels[b]]
	})

	doc := commledger.BuildDoc(profiles, labels, []int{3, 5, 9})
	jb, err := json.MarshalIndent(doc, "", "  ")
	must(err)
	must(os.MkdirAll(filepath.Dir(*out), 0o755))
	must(os.WriteFile(*out, append(jb, '\n'), 0o644))
	fmt.Printf("TAB2 wrote %s (%d rows)\n", *out, len(doc.Summary))
	for _, r := range doc.Summary {
		fmt.Printf("  %-10s n=%d pv=%6d recv=%6d\n", r.Scheme, r.N, r.PVDynBytes, r.RecRecvMinBytes)
	}
	fmt.Printf("TAB2_OK\n")
}
