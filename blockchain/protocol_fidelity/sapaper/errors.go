package sapaper

import (
	"fmt"

	"c5full/blockchain/protocol_fidelity/schemea_faithful"
)

const (
	ErrChannelRoundtrip = "CHANNEL-ROUNDTRIP"
	ErrDecryptMismatch  = "DECRYPT-MISMATCH"
)

func errfChannel() error {
	return &schemeafaithful.ErrFaithful{Code: schemeafaithful.ErrChannel, Msg: "AES channel roundtrip mismatch"}
}

func errfDecrypt(serverIdx int) error {
	return &schemeafaithful.ErrFaithful{Code: schemeafaithful.ErrDecrypt,
		Msg: fmt.Sprintf("recovered z_i != local z_i (server %d) — m-of-m decrypt inconsistent", serverIdx)}
}
