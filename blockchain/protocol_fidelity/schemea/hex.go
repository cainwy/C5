package schemea

import "encoding/hex"

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
