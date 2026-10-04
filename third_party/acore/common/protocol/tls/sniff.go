package tls

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/protocol"
)

type SniffHeader struct {
	domain string
	alpn   string
	// TLS version parsed from ClientHello.
	tlsVersion string
	// JA4 fingerprint for TLS-over-TCP ClientHello.
	ja4 string
}

func (h *SniffHeader) Protocol() string {
	return "tls"
}

func (h *SniffHeader) Domain() string {
	return h.domain
}

func (h *SniffHeader) ALPN() string {
	return h.alpn
}

func (h *SniffHeader) TLSVersion() string {
	return h.tlsVersion
}

func (h *SniffHeader) JA4() string {
	return h.ja4
}

var (
	errNotTLS         = errors.New("not TLS header")
	errNotClientHello = errors.New("not client hello")
)

func IsValidTLSVersion(major, minor byte) bool {
	return major == 3
}

// ReadClientHello returns server name (if any) from TLS client hello message.
// https://github.com/golang/go/blob/master/src/crypto/tls/handshake_messages.go#L300
func ReadClientHello(data []byte, h *SniffHeader) error {
	return readClientHello(data, h, true)
}

// ReadClientHelloWithJA4 parses ClientHello and controls whether JA4 should be computed.
func ReadClientHelloWithJA4(data []byte, h *SniffHeader, enableJA4 bool) error {
	return readClientHello(data, h, enableJA4)
}

func readClientHello(data []byte, h *SniffHeader, enableJA4 bool) error {
	if len(data) < 42 {
		return common.ErrNoClue
	}

	const (
		extensionServerName         = 0x0000
		extensionSignatureAlgorithm = 0x000d
		extensionALPN               = 0x0010
		extensionSupportedVersions  = 0x002b
	)

	// RFC 8446 keeps legacy_version for compatibility. Parse this first so we have a default.
	legacyVersion := binary.BigEndian.Uint16(data[4:6])
	h.tlsVersion = formatTLSVersion(data[4], data[5])
	ja4Version := legacyVersion

	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return common.ErrNoClue
	}
	data = data[39+sessionIDLen:]
	if len(data) < 2 {
		return common.ErrNoClue
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return errNotClientHello
	}
	var ciphers []uint16
	if enableJA4 {
		ciphers = make([]uint16, 0, cipherSuiteLen/2)
		for i := 0; i < cipherSuiteLen; i += 2 {
			c := binary.BigEndian.Uint16(data[2+i : 2+i+2])
			ciphers = append(ciphers, c)
		}
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return common.ErrNoClue
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return common.ErrNoClue
	}
	data = data[1+compressionMethodsLen:]

	if len(data) < 2 {
		return errNotClientHello
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return errNotClientHello
	}

	var extensions []uint16
	var signatureAlgorithms []uint16
	if enableJA4 {
		extensions = make([]uint16, 0, 16)
		signatureAlgorithms = make([]uint16, 0, 8)
	}
	sniPresent := false
	var firstALPN []byte

	for len(data) != 0 {
		if len(data) < 4 {
			return errNotClientHello
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return errNotClientHello
		}
		if enableJA4 {
			extensions = append(extensions, extension)
		}

		if extension == extensionServerName { /* extensionServerName */
			sniPresent = true
			domain, err := parseServerNameExtension(data[:length])
			if err != nil {
				return err
			}
			if domain != "" {
				h.domain = domain
			}
		}
		if extension == extensionALPN { /* extensionALPN */
			// Clash-style tolerance: ALPN parsing should not block SNI recovery.
			// Some clients carry uncommon/invalid ALPN layouts while SNI is still valid.
			if len(firstALPN) == 0 {
				if alpnRaw, err := parseALPNFirstValue(data[:length]); err == nil {
					firstALPN = append(firstALPN, alpnRaw...)
				}
			}
			if h.alpn == "" {
				if alpn, err := parseALPNExtension(data[:length]); err == nil {
					h.alpn = alpn
				}
			}
		}
		if extension == extensionSupportedVersions { /* extensionSupportedVersions */
			extData := data[:length]
			if version := parseSupportedVersionsValue(extData); version != 0 {
				ja4Version = version
			}
			if version := parseTLSVersionExtension(extData); version != "" {
				h.tlsVersion = version
			}
		}
		if enableJA4 && extension == extensionSignatureAlgorithm { /* extensionSignatureAlgorithm */
			if values, err := parseSignatureAlgorithmsExtension(data[:length]); err == nil {
				signatureAlgorithms = values
			}
		}
		data = data[length:]
	}

	if enableJA4 {
		h.ja4 = buildJA4Fingerprint('t', ja4Version, sniPresent, firstALPN, ciphers, extensions, signatureAlgorithms)
	} else {
		h.ja4 = ""
	}

	return nil
}

func parseServerNameExtension(extData []byte) (string, error) {
	if len(extData) < 2 {
		return "", errNotClientHello
	}
	namesLen := int(extData[0])<<8 | int(extData[1])
	d := extData[2:]
	if len(d) != namesLen {
		return "", errNotClientHello
	}
	for len(d) > 0 {
		if len(d) < 3 {
			return "", errNotClientHello
		}
		nameType := d[0]
		nameLen := int(d[1])<<8 | int(d[2])
		d = d[3:]
		if len(d) < nameLen {
			return "", errNotClientHello
		}
		if nameType == 0 {
			if nameLen == 0 {
				return "", errNotClientHello
			}
			serverName := string(d[:nameLen])
			// An SNI value may not include a trailing dot.
			if serverName[len(serverName)-1] == '.' {
				return "", errNotClientHello
			}
			return serverName, nil
		}
		d = d[nameLen:]
	}
	return "", nil
}

func parseALPNExtension(extData []byte) (string, error) {
	alpn, err := parseALPNFirstValue(extData)
	if err != nil {
		return "", err
	}
	return string(alpn), nil
}

func parseALPNFirstValue(extData []byte) ([]byte, error) {
	if len(extData) < 2 {
		return nil, errNotClientHello
	}
	alpnListLen := int(extData[0])<<8 | int(extData[1])
	d := extData[2:]
	if alpnListLen != len(d) {
		return nil, errNotClientHello
	}
	if len(d) == 0 {
		return nil, nil
	}
	nameLen := int(d[0])
	d = d[1:]
	if nameLen == 0 || len(d) < nameLen {
		return nil, errNotClientHello
	}
	return append([]byte(nil), d[:nameLen]...), nil
}

func parseSignatureAlgorithmsExtension(extData []byte) ([]uint16, error) {
	if len(extData) < 2 {
		return nil, errNotClientHello
	}
	sigListLen := int(extData[0])<<8 | int(extData[1])
	d := extData[2:]
	if sigListLen%2 == 1 || sigListLen != len(d) {
		return nil, errNotClientHello
	}
	signatures := make([]uint16, 0, sigListLen/2)
	for i := 0; i < len(d); i += 2 {
		sig := binary.BigEndian.Uint16(d[i : i+2])
		if isGreaseValue(sig) {
			continue
		}
		signatures = append(signatures, sig)
	}
	return signatures, nil
}

func parseSupportedVersionsValue(extData []byte) uint16 {
	if len(extData) < 1 {
		return 0
	}
	// RFC 8446 section 4.2.1: versions is encoded as
	// ProtocolVersion versions<2..254>, where the vector length is 1 byte.
	vLen := int(extData[0])
	if vLen == 0 || (vLen%2) != 0 {
		return 0
	}
	if 1+vLen > len(extData) {
		return 0
	}

	versions := extData[1 : 1+vLen]
	highest := uint16(0)
	for len(versions) >= 2 {
		version := binary.BigEndian.Uint16(versions[:2])
		versions = versions[2:]
		if isGreaseValue(version) {
			continue
		}
		if version > highest {
			highest = version
		}
	}
	return highest
}

func parseTLSVersionExtension(extData []byte) string {
	version := parseSupportedVersionsValue(extData)
	if version == 0 {
		return ""
	}
	return formatTLSVersion(byte(version>>8), byte(version))
}

func buildJA4Fingerprint(transport byte, version uint16, sniPresent bool, firstALPN []byte, ciphers []uint16, extensions []uint16, signatureAlgorithms []uint16) string {
	const (
		ja4MinHash = "000000000000"
	)

	if transport != 't' && transport != 'q' && transport != 'd' {
		transport = 't'
	}
	sni := byte('i')
	if sniPresent {
		sni = 'd'
	}

	cipherHex := formatJA4HexList(ciphers, nil, true)
	cipherHash := ja4MinHash
	if len(cipherHex) > 0 {
		cipherHash = hashJA4Material(strings.Join(cipherHex, ","))
	}

	extensionCountHex := formatJA4HexList(extensions, nil, false)
	extensionExclude := map[uint16]struct{}{
		0x0000: {}, // SNI
		0x0010: {}, // ALPN
	}
	extensionHashHex := formatJA4HexList(extensions, extensionExclude, true)
	signatureHex := formatJA4HexList(signatureAlgorithms, nil, false)
	extensionHash := ja4MinHash
	if len(extensionHashHex) > 0 {
		material := strings.Join(extensionHashHex, ",")
		if len(signatureHex) > 0 {
			material += "_" + strings.Join(signatureHex, ",")
		}
		extensionHash = hashJA4Material(material)
	}

	return fmt.Sprintf(
		"%c%s%c%02d%02d%s_%s_%s",
		transport,
		ja4VersionCode(version),
		sni,
		clampJA4Count(len(cipherHex)),
		clampJA4Count(len(extensionCountHex)),
		ja4ALPNHint(firstALPN),
		cipherHash,
		extensionHash,
	)
}

func isGreaseValue(v uint16) bool {
	major := byte(v >> 8)
	minor := byte(v)
	// GREASE versions have equal bytes and high nibble 0xA.
	return major == minor && (major&0x0f) == 0x0a
}

func formatJA4HexList(values []uint16, exclude map[uint16]struct{}, sortValues bool) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if isGreaseValue(value) {
			continue
		}
		if exclude != nil {
			if _, found := exclude[value]; found {
				continue
			}
		}
		out = append(out, fmt.Sprintf("%04x", value))
	}
	if sortValues {
		sort.Strings(out)
	}
	return out
}

func hashJA4Material(material string) string {
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])[:12]
}

func clampJA4Count(n int) int {
	if n < 0 {
		return 0
	}
	if n > 99 {
		return 99
	}
	return n
}

func ja4ALPNHint(alpn []byte) string {
	if len(alpn) == 0 {
		return "00"
	}
	first := alpn[0]
	last := alpn[len(alpn)-1]
	if isASCIIAlnum(first) && isASCIIAlnum(last) {
		return strings.ToLower(string([]byte{first, last}))
	}
	hexValue := strings.ToLower(hex.EncodeToString(alpn))
	if len(hexValue) == 0 {
		return "00"
	}
	return string([]byte{hexValue[0], hexValue[len(hexValue)-1]})
}

func isASCIIAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func ja4VersionCode(version uint16) string {
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func formatTLSVersion(major, minor byte) string {
	switch {
	case major == 0x03 && minor == 0x00:
		return "3.0"
	case major == 0x03 && minor == 0x01:
		return "1.0"
	case major == 0x03 && minor == 0x02:
		return "1.1"
	case major == 0x03 && minor == 0x03:
		return "1.2"
	case major == 0x03 && minor == 0x04:
		return "1.3"
	default:
		return fmt.Sprintf("0x%02x%02x", major, minor)
	}
}

func SniffTLS(b []byte) (*SniffHeader, error) {
	return SniffTLSWithJA4(b, true)
}

func SniffTLSWithJA4(b []byte, enableJA4 bool) (*SniffHeader, error) {
	const (
		tlsRecordHeaderLen = 5
		tlsHandshakeRecord = 0x16
		tlsClientHello     = 0x01
	)

	if len(b) < tlsRecordHeaderLen {
		// The client may send a fragmented TLS record header (e.g. with packet fragmentation
		// or delayed writes). If it already looks like a TLS handshake record, ask the
		// dispatcher to keep buffering more bytes instead of counting as a failed attempt.
		if len(b) > 0 && b[0] == tlsHandshakeRecord {
			if len(b) == 1 || b[1] == 0x03 {
				return nil, protocol.NewNeedMoreDataError(tlsRecordHeaderLen)
			}
		}
		return nil, common.ErrNoClue
	}

	// Fast path: a complete ClientHello contained in the first record.
	if b[0] == tlsHandshakeRecord && IsValidTLSVersion(b[1], b[2]) {
		headerLen := int(binary.BigEndian.Uint16(b[3:5]))
		if headerLen > 0 {
			if needed := tlsRecordHeaderLen + headerLen; needed > len(b) {
				return nil, protocol.NewNeedMoreDataError(needed)
			}
			h := &SniffHeader{}
			if err := readClientHello(b[tlsRecordHeaderLen:tlsRecordHeaderLen+headerLen], h, enableJA4); err == nil {
				return h, nil
			}
		}
	}

	// Slow path: the ClientHello may be fragmented across multiple TLS records.
	// Assemble the handshake message bytes across consecutive handshake records.
	var (
		segments     [][]byte
		segLen       int
		need         int = -1
		hdr          [4]byte
		hdrCaptured  bool
		sawTLSHeader bool
		needLenHint  int
	)

	offset := 0
	for offset+tlsRecordHeaderLen <= len(b) {

		if b[offset] != tlsHandshakeRecord {
			if offset == 0 {
				return nil, errNotTLS
			}
			break
		}
		if !IsValidTLSVersion(b[offset+1], b[offset+2]) {
			return nil, errNotTLS
		}
		sawTLSHeader = true

		recordLen := int(binary.BigEndian.Uint16(b[offset+3 : offset+5]))
		if offset+tlsRecordHeaderLen+recordLen > len(b) {
			// Incomplete record in buffer.
			needLenHint = offset + tlsRecordHeaderLen + recordLen
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
				// segLen should guarantee copied>=4, but keep it defensive.
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
		// Not enough bytes to determine the handshake message size yet.
		// If it already looks like TLS, keep buffering.
		if sawTLSHeader {
			if needLenHint > len(b) {
				return nil, protocol.NewNeedMoreDataError(needLenHint)
			}
			return nil, protocol.ErrProtoNeedMoreData
		}
		return nil, common.ErrNoClue
	}
	if segLen < need {
		// We already know this is a ClientHello, but we need more records/bytes.
		// Signal the dispatcher to keep reading without consuming the sniffing attempts.
		if hdrCaptured {
			if needLenHint > len(b) {
				return nil, protocol.NewNeedMoreDataError(needLenHint)
			}
			return nil, protocol.ErrProtoNeedMoreData
		}
		return nil, common.ErrNoClue
	}

	var handshake []byte
	if len(segments) > 0 && len(segments[0]) >= need {
		handshake = segments[0][:need]
	} else {
		handshake = make([]byte, need)
		n := 0
		for _, s := range segments {
			if n >= need {
				break
			}
			n += copy(handshake[n:], s)
		}
	}

	h := &SniffHeader{}
	if err := readClientHello(handshake, h, enableJA4); err != nil {
		return nil, err
	}
	return h, nil
}
