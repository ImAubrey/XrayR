package dispatcher

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/ImAubrey/acore/common"
	xnet "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
)

type zeroTierSniffResult struct{}

func (zeroTierSniffResult) Protocol() string { return "zerotier" }
func (zeroTierSniffResult) Domain() string   { return "" }

var errNotZeroTier = errors.New("not zerotier header")

const (
	ztAddressLength = 5

	ztPacketIdxDest   = 8
	ztPacketIdxSource = 13
	ztPacketIdxFlags  = 18
	ztPacketIdxVerb   = 27
	ztPacketIdxPay    = 28

	ztPacketIdxHelloTimestamp = ztPacketIdxPay + 1 + 1 + 1 + 2 // protoVer + major + minor + revision(u16)

	ztHelloVerb         = 0x01
	ztProtoVersionMin   = 4
	ztAddrReservedFirst = 0xff
	ztDefaultPort       = xnet.Port(9993)

	// 2000-01-01 00:00:00 UTC .. 2100-01-01 00:00:00 UTC (milliseconds since epoch).
	ztHelloTimestampMinMs = int64(946684800000)
	ztHelloTimestampMaxMs = int64(4102444800000)
)

func hasZeroTierPort(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		if inbound.Source.Port == ztDefaultPort || inbound.Local.Port == ztDefaultPort {
			return true
		}
	}
	outbounds := session.OutboundsFromContext(ctx)
	for i := len(outbounds) - 1; i >= 0; i-- {
		ob := outbounds[i]
		if ob == nil {
			continue
		}
		if ob.Target.Port == ztDefaultPort || ob.OriginalTarget.Port == ztDefaultPort {
			return true
		}
	}
	return false
}

func isReservedZTAddress(b []byte) bool {
	if len(b) < ztAddressLength {
		return true
	}
	if b[0] == ztAddrReservedFirst {
		return true
	}
	for i := 0; i < ztAddressLength; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}

func hasBytesAt(b []byte, start int, size int) bool {
	if start < 0 || size < 0 {
		return false
	}
	end := start + size
	return end >= start && end <= len(b)
}

// sniffZeroTier attempts to identify a ZeroTier UDP packet by its on-wire header.
// This intentionally does not bind to a specific port.
func sniffZeroTier(ctx context.Context, b []byte) (SniffResult, error) {
	// Need enough bytes to recognize at least a fragment header.
	if len(b) < 16 {
		return nil, common.ErrNoClue
	}

	// Fragment header (16 bytes):
	// [0..7]   packetId/IV
	// [8..12]  dest address (5 bytes)
	// [13]     fragment indicator (0xff)
	// [14]     fragment no/total (4 bits each)
	// [15]     hops (0..7)
	if b[13] == 0xff {
		if !hasBytesAt(b, ztPacketIdxDest, ztAddressLength) {
			return nil, common.ErrNoClue
		}
		if isReservedZTAddress(b[ztPacketIdxDest : ztPacketIdxDest+ztAddressLength]) {
			return nil, errNotZeroTier
		}
		fragNoTotal := b[14]
		fragTotal := (fragNoTotal >> 4) & 0x0f
		fragNo := fragNoTotal & 0x0f
		hops := b[15]
		if fragTotal >= 2 && fragTotal <= 15 && fragNo < fragTotal && hops <= 7 {
			return zeroTierSniffResult{}, nil
		}
		return nil, errNotZeroTier
	}

	// Do not hard-match by port. 9993 is commonly used by ZeroTier but is not exclusive.
	// Keep port as a strict hint: if the packet doesn't even look like a valid ZeroTier
	// envelope, reject it even when destination/source is 9993.
	if hasZeroTierPort(ctx) {
		if !hasBytesAt(b, ztPacketIdxFlags, 1) ||
			!hasBytesAt(b, ztPacketIdxDest, ztAddressLength) ||
			!hasBytesAt(b, ztPacketIdxSource, ztAddressLength) {
			return nil, common.ErrNoClue
		}
		if isReservedZTAddress(b[ztPacketIdxDest:ztPacketIdxDest+ztAddressLength]) ||
			isReservedZTAddress(b[ztPacketIdxSource:ztPacketIdxSource+ztAddressLength]) {
			return nil, errNotZeroTier
		}
		flags := b[ztPacketIdxFlags]
		cipher := (flags & 0x38) >> 3
		if cipher <= 3 {
			return zeroTierSniffResult{}, nil
		}
		return nil, errNotZeroTier
	}

	// Plain HELLO packet signature (unencrypted HELLO on wire):
	// - cipher suite is C25519/Poly1305/NONE (0)
	// - extended armor is off (else verb/payload are encrypted on wire)
	// - verb is HELLO (0x01)
	// - protocol version >= 4
	// - timestamp looks like ms-since-epoch in a sane range
	if !hasBytesAt(b, ztPacketIdxFlags, 1) ||
		!hasBytesAt(b, ztPacketIdxDest, ztAddressLength) ||
		!hasBytesAt(b, ztPacketIdxSource, ztAddressLength) ||
		!hasBytesAt(b, ztPacketIdxVerb, 1) ||
		!hasBytesAt(b, ztPacketIdxPay, 1) ||
		!hasBytesAt(b, ztPacketIdxHelloTimestamp, 8) {
		return nil, common.ErrNoClue
	}

	flags := b[ztPacketIdxFlags]
	if (flags & 0x80) != 0 { // Extended armor on: cannot parse verb/timestamp without keys.
		return nil, errNotZeroTier
	}
	cipher := (flags & 0x38) >> 3
	if cipher != 0 {
		return nil, errNotZeroTier
	}
	if isReservedZTAddress(b[ztPacketIdxDest:ztPacketIdxDest+ztAddressLength]) ||
		isReservedZTAddress(b[ztPacketIdxSource:ztPacketIdxSource+ztAddressLength]) {
		return nil, errNotZeroTier
	}
	if (b[ztPacketIdxVerb] & 0x1f) != ztHelloVerb {
		return nil, errNotZeroTier
	}
	if b[ztPacketIdxPay] < ztProtoVersionMin {
		return nil, errNotZeroTier
	}
	ts := int64(binary.BigEndian.Uint64(b[ztPacketIdxHelloTimestamp : ztPacketIdxHelloTimestamp+8]))
	if ts < ztHelloTimestampMinMs || ts > ztHelloTimestampMaxMs {
		return nil, errNotZeroTier
	}

	return zeroTierSniffResult{}, nil
}
