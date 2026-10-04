package dtls

import (
	"encoding/binary"
	"errors"

	"github.com/ImAubrey/acore/common"
)

type SniffHeader struct{}

func (*SniffHeader) Protocol() string { return "dtls" }

// Domain returns empty to avoid destination override.
func (*SniffHeader) Domain() string { return "" }

var errNotDTLS = errors.New("not dtls")

func isDTLSContentType(t byte) bool {
	switch t {
	case 20, 21, 22, 23: // change_cipher_spec, alert, handshake, application_data
		return true
	default:
		return false
	}
}

func isDTLSVersion(major, minor byte) bool {
	// DTLS versions use inverted numbering. Common values:
	// DTLS 1.0: 0xfeff, DTLS 1.1: 0xfefe, DTLS 1.2: 0xfefd.
	return major == 0xfe && (minor == 0xff || minor == 0xfe || minor == 0xfd)
}

func SniffDTLS(b []byte) (*SniffHeader, error) {
	// DTLS record header is 13 bytes.
	if len(b) < 1 {
		return nil, common.ErrNoClue
	}
	if !isDTLSContentType(b[0]) {
		return nil, errNotDTLS
	}
	if len(b) < 3 {
		return nil, common.ErrNoClue
	}
	if !isDTLSVersion(b[1], b[2]) {
		return nil, errNotDTLS
	}
	if len(b) < 13 {
		return nil, common.ErrNoClue
	}
	// Length is the size of the record fragment.
	fragLen := int(binary.BigEndian.Uint16(b[11:13]))
	if 13+fragLen > len(b) {
		return nil, common.ErrNoClue
	}
	return &SniffHeader{}, nil
}
