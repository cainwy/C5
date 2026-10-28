// common.go holds the identifiers and timing helpers shared by the Fig. 2 run.
package offline

import (
	"c5full/blockchain/protocol_fidelity/sapaper"
)

// nsX2 is the server-count grid used by Fig. 2 and Table 2.
var nsX2 = []int{3, 5, 9}

func msSinceQPC(start int64) float64 {
	return qpcElapsedUS(start, qpcNow()) / 1000
}

func metaID(pk sapaper.ProfileKind) string {
	switch pk {
	case sapaper.ProfileP:
		return "P"
	case sapaper.ProfileN:
		return "N"
	case sapaper.ProfileM:
		return "M"
	default:
		return "S"
	}
}

func kindName(pk sapaper.ProfileKind) string {
	switch pk {
	case sapaper.ProfileP:
		return "paper-oriented"
	case sapaper.ProfileN:
		return "security-normalized"
	case sapaper.ProfileM:
		return "paper-1024"
	default:
		return "wide-share-stress"
	}
}
