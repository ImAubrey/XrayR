package postgres

import (
	"encoding/binary"
	"errors"

	"github.com/ImAubrey/acore/common"
)

type SniffHeader struct {
	protocol string
}

func (h *SniffHeader) Protocol() string { return h.protocol }

// Domain returns empty to avoid destination override.
func (*SniffHeader) Domain() string { return "" }

var errNotPostgres = errors.New("not postgres")

const (
	sslRequestCode    uint32 = 80877103 // 0x04d2162f
	cancelRequestCode uint32 = 80877102 // 0x04d2162e
	gssEncRequestCode uint32 = 80877104 // 0x04d21630

	protocolVersion30 uint32 = 0x00030000
)

func SniffPostgres(b []byte) (*SniffHeader, error) {
	// StartupMessage / SSLRequest are client-first. We only need the first 8 bytes.
	if len(b) < 8 {
		// Length is big-endian. For typical startup messages it's a small integer,
		// so the highest byte is usually 0.
		if len(b) > 0 && b[0] != 0x00 {
			return nil, errNotPostgres
		}
		return nil, common.ErrNoClue
	}

	msgLen := binary.BigEndian.Uint32(b[0:4])
	if msgLen < 8 {
		return nil, errNotPostgres
	}
	// Defensive upper bound to avoid false positives on random data.
	if msgLen > 1024*1024 {
		return nil, errNotPostgres
	}

	code := binary.BigEndian.Uint32(b[4:8])
	switch code {
	case protocolVersion30:
		return &SniffHeader{protocol: "postgres"}, nil
	case sslRequestCode:
		if msgLen != 8 {
			return nil, errNotPostgres
		}
		return &SniffHeader{protocol: "postgres+ssl"}, nil
	case gssEncRequestCode:
		if msgLen != 8 {
			return nil, errNotPostgres
		}
		return &SniffHeader{protocol: "postgres+gssenc"}, nil
	case cancelRequestCode:
		if msgLen != 16 {
			return nil, errNotPostgres
		}
		return &SniffHeader{protocol: "postgres+cancel"}, nil
	default:
		return nil, errNotPostgres
	}
}
