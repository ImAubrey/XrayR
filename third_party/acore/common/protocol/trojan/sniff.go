package trojan

import (
	"encoding/binary"
	"errors"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/protocol"
	ptls "github.com/ImAubrey/acore/common/protocol/tls"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "trojan"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var (
	errNotTrojan      = errors.New("not trojan")
	errNotTLS         = errors.New("not TLS header")
	errNotClientHello = errors.New("not client hello")
)

const (
	minCipherSuites = 10
	maxCipherSuites = 20
)

type clientHelloInfo struct {
	hasSNI       bool
	hasALPN      bool
	hasGrease    bool
	cipherSuites int
}

// SniffTrojan attempts to detect Trojan-like TLS client hellos.
// It is a heuristic and intentionally conservative to avoid false positives.
func SniffTrojan(b []byte) (*SniffHeader, error) {
	info, err := parseClientHello(b)
	if err != nil {
		if err == errNotTLS || err == errNotClientHello {
			return nil, errNotTrojan
		}
		return nil, err
	}

	if !info.hasSNI {
		return nil, errNotTrojan
	}
	if info.hasALPN {
		return nil, errNotTrojan
	}
	if info.hasGrease {
		return nil, errNotTrojan
	}
	if info.cipherSuites < minCipherSuites || info.cipherSuites > maxCipherSuites {
		return nil, errNotTrojan
	}

	return &SniffHeader{}, nil
}

func parseClientHello(b []byte) (clientHelloInfo, error) {
	var info clientHelloInfo
	handshake, err := readClientHelloHandshake(b)
	if err != nil {
		return info, err
	}
	if len(handshake) < 4 {
		return info, common.ErrNoClue
	}
	if handshake[0] != 0x01 {
		return info, errNotClientHello
	}
	helloLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if helloLen+4 > len(handshake) {
		return info, common.ErrNoClue
	}
	ch := handshake[4 : 4+helloLen]
	if len(ch) < 2+32+1 {
		return info, common.ErrNoClue
	}

	pos := 2 + 32
	sessionIDLen := int(ch[pos])
	pos++
	if len(ch) < pos+sessionIDLen {
		return info, common.ErrNoClue
	}
	pos += sessionIDLen

	if len(ch) < pos+2 {
		return info, common.ErrNoClue
	}
	cipherLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2
	if cipherLen%2 == 1 || len(ch) < pos+cipherLen {
		return info, errNotClientHello
	}
	info.cipherSuites = cipherLen / 2
	for i := 0; i+1 < cipherLen; i += 2 {
		if isGREASE(binary.BigEndian.Uint16(ch[pos+i : pos+i+2])) {
			info.hasGrease = true
		}
	}
	pos += cipherLen

	if len(ch) < pos+1 {
		return info, common.ErrNoClue
	}
	compressionLen := int(ch[pos])
	pos++
	if len(ch) < pos+compressionLen {
		return info, common.ErrNoClue
	}
	pos += compressionLen

	if len(ch) < pos+2 {
		return info, nil
	}
	extLen := int(ch[pos])<<8 | int(ch[pos+1])
	pos += 2
	if len(ch) < pos+extLen {
		return info, common.ErrNoClue
	}
	extData := ch[pos : pos+extLen]
	for len(extData) > 0 {
		if len(extData) < 4 {
			return info, errNotClientHello
		}
		extType := binary.BigEndian.Uint16(extData[0:2])
		extSize := int(binary.BigEndian.Uint16(extData[2:4]))
		extData = extData[4:]
		if len(extData) < extSize {
			return info, errNotClientHello
		}
		if isGREASE(extType) {
			info.hasGrease = true
		}
		switch extType {
		case 0x00:
			if !info.hasSNI && hasServerName(extData[:extSize]) {
				info.hasSNI = true
			}
		case 0x10:
			info.hasALPN = true
		}
		extData = extData[extSize:]
	}

	return info, nil
}

func readClientHelloHandshake(b []byte) ([]byte, error) {
	const (
		tlsRecordHeaderLen = 5
		tlsHandshakeRecord = 0x16
		tlsClientHello     = 0x01
	)

	if len(b) < tlsRecordHeaderLen {
		return nil, common.ErrNoClue
	}
	if b[0] != tlsHandshakeRecord {
		return nil, errNotTLS
	}
	if !ptls.IsValidTLSVersion(b[1], b[2]) {
		return nil, errNotTLS
	}

	// Fast path: ClientHello fully contained in the first record.
	firstLen := int(binary.BigEndian.Uint16(b[3:5]))
	if tlsRecordHeaderLen+firstLen <= len(b) && firstLen > 0 {
		payload := b[tlsRecordHeaderLen : tlsRecordHeaderLen+firstLen]
		if len(payload) >= 4 && payload[0] == tlsClientHello {
			helloLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
			need := 4 + helloLen
			if need <= len(payload) {
				return payload[:need], nil
			}
		}
	}

	// Slow path: ClientHello fragmented across multiple handshake records.
	var (
		segments    [][]byte
		segLen      int
		need        int = -1
		hdr         [4]byte
		hdrCaptured bool
	)

	offset := 0
	for offset+tlsRecordHeaderLen <= len(b) {
		if b[offset] != tlsHandshakeRecord {
			if offset == 0 {
				return nil, errNotTLS
			}
			break
		}
		if !ptls.IsValidTLSVersion(b[offset+1], b[offset+2]) {
			return nil, errNotTLS
		}

		recordLen := int(binary.BigEndian.Uint16(b[offset+3 : offset+5]))
		if offset+tlsRecordHeaderLen+recordLen > len(b) {
			break
		}

		payload := b[offset+tlsRecordHeaderLen : offset+tlsRecordHeaderLen+recordLen]
		if len(payload) > 0 {
			segments = append(segments, payload)
			segLen += len(payload)
		}

		if need < 0 && segLen >= 4 {
			copied := 0
			for _, s := range segments {
				if copied >= 4 {
					break
				}
				copied += copy(hdr[copied:], s)
			}
			if copied < 4 {
				break
			}
			hdrCaptured = true
			if hdr[0] != tlsClientHello {
				return nil, errNotClientHello
			}
			helloLen := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
			need = 4 + helloLen
		}

		if need >= 0 && segLen >= need {
			break
		}

		offset += tlsRecordHeaderLen + recordLen
	}

	if need < 0 {
		return nil, common.ErrNoClue
	}
	if segLen < need {
		if hdrCaptured {
			return nil, protocol.ErrProtoNeedMoreData
		}
		return nil, common.ErrNoClue
	}

	if len(segments) > 0 && len(segments[0]) >= need {
		return segments[0][:need], nil
	}
	handshake := make([]byte, need)
	n := 0
	for _, s := range segments {
		if n >= need {
			break
		}
		n += copy(handshake[n:], s)
	}
	return handshake, nil
}

func hasServerName(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	namesLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != namesLen {
		return false
	}
	for len(data) > 0 {
		if len(data) < 3 {
			return false
		}
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[3:]
		if len(data) < nameLen {
			return false
		}
		if nameType == 0 && nameLen > 0 {
			return true
		}
		data = data[nameLen:]
	}
	return false
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}
