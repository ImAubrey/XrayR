package ike

import (
	"encoding/binary"
	"errors"
)

type SniffHeader struct{}

func (*SniffHeader) Protocol() string { return "ikev2" }

// Domain returns empty to avoid destination override.
func (*SniffHeader) Domain() string { return "" }

var errNotIKEv2 = errors.New("not ikev2")

func isIKEv2ExchangeType(t byte) bool {
	// Common IKEv2 exchange types.
	switch t {
	case 34, 35, 36, 37: // IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL
		return true
	default:
		return false
	}
}

func SniffIKEv2(b []byte) (*SniffHeader, error) {
	// IKE header is 28 bytes.
	if len(b) < 28 {
		return nil, errNotIKEv2
	}
	// Version byte: major.minor, IKEv2 is 0x20.
	if b[17] != 0x20 {
		return nil, errNotIKEv2
	}
	if !isIKEv2ExchangeType(b[18]) {
		return nil, errNotIKEv2
	}
	msgLen := binary.BigEndian.Uint32(b[24:28])
	if msgLen < 28 {
		return nil, errNotIKEv2
	}
	return &SniffHeader{}, nil
}
