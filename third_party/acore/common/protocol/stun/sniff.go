package stun

import (
	"encoding/binary"
	"errors"

	"github.com/ImAubrey/acore/common"
)

type SniffHeader struct {
	protocol string
}

func (h *SniffHeader) Protocol() string {
	return h.protocol
}

func (h *SniffHeader) Domain() string {
	return ""
}

const stunMagicCookie = 0x2112A442

var errNotSTUN = errors.New("not stun")

func SniffSTUN(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if b[0]&0xC0 != 0 {
		return nil, errNotSTUN
	}

	msgType := binary.BigEndian.Uint16(b[0:2])
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	if binary.BigEndian.Uint32(b[4:8]) != stunMagicCookie {
		return nil, errNotSTUN
	}
	if msgLen%4 != 0 {
		return nil, errNotSTUN
	}
	if len(b) < 20+msgLen {
		return nil, common.ErrNoClue
	}

	protocol := "stun"
	if isTURNMethod(stunMethod(msgType)) {
		protocol = "turn"
	}
	return &SniffHeader{protocol: protocol}, nil
}

func stunMethod(t uint16) uint16 {
	return (t & 0x000F) | ((t & 0x00E0) >> 1) | ((t & 0x3E00) >> 2)
}

func isTURNMethod(method uint16) bool {
	switch method {
	case 0x003, 0x004, 0x006, 0x007, 0x008, 0x009, 0x00A, 0x00B, 0x00C:
		return true
	default:
		return false
	}
}
