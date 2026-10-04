package ech

import (
	"encoding/binary"
	"errors"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/protocol/tls"
)

// ECH (Encrypted Client Hello) extension type.
// See IANA TLS ExtensionType registry: "encrypted_client_hello" (0xfe0d).
const extensionEncryptedClientHello uint16 = 0xfe0d

type SniffHeader struct {
	alpn string
}

func (h *SniffHeader) Protocol() string { return "ech" }

// Domain intentionally returns empty to avoid destination override.
// With ECH, the real SNI is encrypted (Inner ClientHello), and relying on Outer SNI
// can lead to incorrect routing/dial behavior.
func (h *SniffHeader) Domain() string { return "" }

func (h *SniffHeader) ALPN() string { return h.alpn }

var (
	errNotECH         = errors.New("not ECH")
	errNotClientHello = errors.New("not client hello")
)

// readClientHelloECH checks whether ClientHello contains the ECH extension.
// It also extracts ALPN (if present) to preserve ALPN-based routing behavior.
func readClientHelloECH(data []byte, h *SniffHeader) (bool, error) {
	// ClientHello starts with handshake header (1 + 3 bytes), then version (2), random (32), ...
	if len(data) < 42 {
		return false, common.ErrNoClue
	}
	if data[0] != 0x01 { // handshakeTypeClientHello
		return false, errNotClientHello
	}

	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return false, common.ErrNoClue
	}
	data = data[39+sessionIDLen:]

	if len(data) < 2 {
		return false, common.ErrNoClue
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers (uint16s), must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false, errNotClientHello
	}
	data = data[2+cipherSuiteLen:]

	if len(data) < 1 {
		return false, common.ErrNoClue
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false, common.ErrNoClue
	}
	data = data[1+compressionMethodsLen:]

	if len(data) < 2 {
		return false, errNotClientHello
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false, errNotClientHello
	}

	hasECH := false
	for len(data) != 0 {
		if len(data) < 4 {
			return false, errNotClientHello
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false, errNotClientHello
		}
		extData := data[:length]

		if extension == extensionEncryptedClientHello {
			hasECH = true
		}
		if extension == 0x10 { /* extensionALPN */
			d := extData
			if len(d) < 2 {
				return false, errNotClientHello
			}
			alpnListLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if alpnListLen != len(d) {
				return false, errNotClientHello
			}
			for len(d) > 0 {
				if len(d) < 1 {
					return false, errNotClientHello
				}
				nameLen := int(d[0])
				d = d[1:]
				if nameLen == 0 || len(d) < nameLen {
					return false, errNotClientHello
				}
				// Keep the first ALPN.
				if h.alpn == "" {
					h.alpn = string(d[:nameLen])
				}
				d = d[nameLen:]
			}
		}

		data = data[length:]
	}

	return hasECH, nil
}

func SniffECH(b []byte) (*SniffHeader, error) {
	if len(b) < 5 {
		return nil, common.ErrNoClue
	}

	if b[0] != 0x16 /* TLS Handshake */ {
		return nil, errNotECH
	}
	if !tls.IsValidTLSVersion(b[1], b[2]) {
		return nil, errNotECH
	}
	headerLen := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+headerLen > len(b) {
		return nil, common.ErrNoClue
	}

	h := &SniffHeader{}
	hasECH, err := readClientHelloECH(b[5:5+headerLen], h)
	if err != nil {
		return nil, err
	}
	if !hasECH {
		return nil, errNotECH
	}
	return h, nil
}
