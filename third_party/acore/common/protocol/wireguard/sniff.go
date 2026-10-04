package wireguard

import (
	"errors"

	"github.com/ImAubrey/acore/common"
)

const (
	messageTypeHandshakeInitiation = 1
	messageTypeHandshakeResponse   = 2
	messageTypeCookieReply         = 3
	messageTypeTransportData       = 4

	// Message sizes defined by WireGuard protocol.
	handshakeInitiationSize = 148
	handshakeResponseSize   = 92
	cookieReplySize         = 64
	transportDataMinSize    = 32
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "wireguard"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotWireGuard = errors.New("not wireguard header")

func SniffWireGuard(b []byte) (*SniffHeader, error) {
	if len(b) < 4 {
		return nil, common.ErrNoClue
	}

	// WireGuard message type is little-endian uint32 with top 3 bytes as zero.
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return nil, errNotWireGuard
	}

	switch b[0] {
	case messageTypeHandshakeInitiation:
		if len(b) < handshakeInitiationSize {
			return nil, common.ErrNoClue
		}
	case messageTypeHandshakeResponse:
		if len(b) < handshakeResponseSize {
			return nil, common.ErrNoClue
		}
	case messageTypeCookieReply:
		if len(b) < cookieReplySize {
			return nil, common.ErrNoClue
		}
	case messageTypeTransportData:
		if len(b) < transportDataMinSize {
			return nil, common.ErrNoClue
		}
	default:
		return nil, errNotWireGuard
	}

	return &SniffHeader{}, nil
}
