package rdp

import (
	"encoding/binary"
	"errors"

	"github.com/ImAubrey/acore/common"
)

// RDP typically starts with a TPKT header (RFC 1006) followed by X.224 COTP.
//
// This sniffer is intentionally conservative: it only matches the common client
// Connection Request pattern used by RDP.
type SniffHeader struct{}

func (*SniffHeader) Protocol() string { return "rdp" }

// Domain returns empty to avoid destination override.
func (*SniffHeader) Domain() string { return "" }

var errNotRDP = errors.New("not rdp")

func SniffRDP(b []byte) (*SniffHeader, error) {
	// Need at least TPKT header.
	if len(b) < 4 {
		return nil, common.ErrNoClue
	}
	// TPKT header: version=3, reserved=0.
	if b[0] != 0x03 || b[1] != 0x00 {
		return nil, errNotRDP
	}
	tpktLen := int(binary.BigEndian.Uint16(b[2:4]))
	// Minimal TPKT length for X.224 Connection Request is >= 11.
	if tpktLen < 11 {
		return nil, errNotRDP
	}
	if len(b) < tpktLen {
		return nil, common.ErrNoClue
	}
	// X.224: length indicator then TPDU type at b[5].
	if tpktLen < 6 {
		return nil, errNotRDP
	}
	lengthIndicator := int(b[4])
	// Must at least cover TPDU type + dst/src refs + class option.
	if lengthIndicator < 6 {
		return nil, errNotRDP
	}
	// Ensure the indicated header length fits inside this TPKT packet.
	if 4+1+lengthIndicator > tpktLen {
		return nil, errNotRDP
	}
	// X.224 Connection Request TPDU type.
	if b[5] != 0xe0 {
		return nil, errNotRDP
	}
	return &SniffHeader{}, nil
}
