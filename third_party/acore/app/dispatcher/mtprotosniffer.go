package dispatcher

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/protocol"
)

type mtProtoSniffResult struct{}

func (mtProtoSniffResult) Protocol() string { return "mtproto" }
func (mtProtoSniffResult) Domain() string   { return "" }

var errNotMTProto = errors.New("not mtproto header")

const (
	mtProtoAbridgedTag     = 0xef
	mtProtoIntermediateTag = 0xee
	mtProtoPaddedTag       = 0xdd

	mtProtoMinPacketLen = 4
	// Keep a conservative upper bound to reduce false positives on random TCP payloads.
	mtProtoMaxPacketLen = 16 * 1024 * 1024
)

func validMTProtoPacketLen(n int) bool {
	return n >= mtProtoMinPacketLen && n <= mtProtoMaxPacketLen && n%4 == 0
}

// sniffMTProto identifies plaintext MTProto TCP transport headers.
// It intentionally does not attempt to detect MTProxy-obfuscated/fake-tls traffic.
func sniffMTProto(_ context.Context, b []byte) (SniffResult, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	// Abridged transport:
	// [0] = 0xef, then length in 4-byte words (1 byte, or 0x7f + 3 bytes LE).
	if b[0] == mtProtoAbridgedTag {
		if len(b) < 2 {
			return nil, protocol.ErrProtoNeedMoreData
		}
		if b[1] < 0x7f {
			packetLen := int(b[1]) * 4
			if !validMTProtoPacketLen(packetLen) {
				return nil, errNotMTProto
			}
			if len(b) < 2+packetLen {
				return nil, protocol.ErrProtoNeedMoreData
			}
			return mtProtoSniffResult{}, nil
		}
		if b[1] != 0x7f {
			return nil, errNotMTProto
		}
		if len(b) < 5 {
			return nil, protocol.ErrProtoNeedMoreData
		}
		words := int(b[2]) | int(b[3])<<8 | int(b[4])<<16
		packetLen := words * 4
		if !validMTProtoPacketLen(packetLen) {
			return nil, errNotMTProto
		}
		if len(b) < 5+packetLen {
			return nil, protocol.ErrProtoNeedMoreData
		}
		return mtProtoSniffResult{}, nil
	}

	// Intermediate / Padded Intermediate transport:
	// [0..3] = 0xeeeeeeee or 0xdddddddd, then packet length uint32 LE.
	if len(b) < 4 {
		return nil, common.ErrNoClue
	}
	isIntermediate := b[0] == mtProtoIntermediateTag &&
		b[1] == mtProtoIntermediateTag &&
		b[2] == mtProtoIntermediateTag &&
		b[3] == mtProtoIntermediateTag
	isPadded := b[0] == mtProtoPaddedTag &&
		b[1] == mtProtoPaddedTag &&
		b[2] == mtProtoPaddedTag &&
		b[3] == mtProtoPaddedTag
	if !isIntermediate && !isPadded {
		return nil, errNotMTProto
	}
	if len(b) < 8 {
		return nil, protocol.ErrProtoNeedMoreData
	}
	packetLen := int(binary.LittleEndian.Uint32(b[4:8]))
	if !validMTProtoPacketLen(packetLen) {
		return nil, errNotMTProto
	}
	if len(b) < 8+packetLen {
		return nil, protocol.ErrProtoNeedMoreData
	}

	return mtProtoSniffResult{}, nil
}
