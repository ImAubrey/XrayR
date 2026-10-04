package mqtt

import (
	"errors"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/protocol"
)

type SniffHeader struct{}

func (*SniffHeader) Protocol() string { return "mqtt" }

// Domain returns empty to avoid destination override.
func (*SniffHeader) Domain() string { return "" }

var errNotMQTT = errors.New("not mqtt")

// decodeRemainingLength parses MQTT "Remaining Length" varint.
// It returns (value, bytesUsed, ok, needMore).
func decodeRemainingLength(b []byte) (int, int, bool, bool) {
	multiplier := 1
	value := 0
	for i := 0; i < 4; i++ {
		if i >= len(b) {
			return 0, 0, false, true
		}
		encodedByte := int(b[i])
		value += (encodedByte & 127) * multiplier
		if encodedByte&128 == 0 {
			return value, i + 1, true, false
		}
		multiplier *= 128
	}
	// Malformed: more than 4 bytes or continuation bit set on 4th byte.
	return 0, 0, false, false
}

func SniffMQTT(b []byte) (*SniffHeader, error) {
	if len(b) < 2 {
		return nil, common.ErrNoClue
	}
	// CONNECT packet type is 1 with flags 0: 0x10.
	if b[0] != 0x10 {
		return nil, errNotMQTT
	}

	rl, rlBytes, ok, needMore := decodeRemainingLength(b[1:])
	if needMore {
		return nil, common.ErrNoClue
	}
	if !ok {
		return nil, errNotMQTT
	}
	fixedHeaderLen := 1 + rlBytes
	if len(b) < fixedHeaderLen {
		return nil, common.ErrNoClue
	}
	if rl < 10 { // minimal variable header for MQTT (protocol name + level + flags + keepalive)
		return nil, errNotMQTT
	}
	if len(b) < fixedHeaderLen+rl {
		// Looks like a CONNECT, but we need more bytes to verify.
		return nil, protocol.ErrProtoNeedMoreData
	}

	pos := fixedHeaderLen
	if pos+2 > len(b) {
		return nil, protocol.ErrProtoNeedMoreData
	}
	protoNameLen := int(b[pos])<<8 | int(b[pos+1])
	pos += 2
	// Only accept standard MQTT protocol names.
	if protoNameLen != 4 && protoNameLen != 6 {
		return nil, errNotMQTT
	}
	if pos+protoNameLen > len(b) {
		return nil, protocol.ErrProtoNeedMoreData
	}
	protoName := string(b[pos : pos+protoNameLen])
	pos += protoNameLen
	if protoName != "MQTT" && protoName != "MQIsdp" {
		return nil, errNotMQTT
	}
	if pos+1+1+2 > len(b) { // level + flags + keepalive
		return nil, protocol.ErrProtoNeedMoreData
	}
	level := b[pos]
	pos++
	flags := b[pos]
	pos++
	// Validate protocol level.
	switch protoName {
	case "MQTT":
		if level != 4 && level != 5 {
			return nil, errNotMQTT
		}
	case "MQIsdp":
		if level != 3 {
			return nil, errNotMQTT
		}
	}
	// Reserved bit must be 0.
	if flags&0x01 != 0 {
		return nil, errNotMQTT
	}
	// If Will Flag is 0, Will QoS and Will Retain must be 0.
	if flags&0x04 == 0 {
		if flags&0x38 != 0 { // bits 3..5
			return nil, errNotMQTT
		}
	} else {
		// Will QoS must be 0,1,2.
		willQos := (flags >> 3) & 0x03
		if willQos == 3 {
			return nil, errNotMQTT
		}
	}
	// keepalive exists but is not validated further.
	_ = b[pos : pos+2]

	return &SniffHeader{}, nil
}
