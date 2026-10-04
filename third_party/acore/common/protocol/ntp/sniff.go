package ntp

import (
	"errors"

	"github.com/ImAubrey/acore/common"
)

type SniffHeader struct{}

func (*SniffHeader) Protocol() string { return "ntp" }

// Domain returns empty to avoid destination override.
func (*SniffHeader) Domain() string { return "" }

var errNotNTP = errors.New("not ntp")

func SniffNTP(b []byte) (*SniffHeader, error) {
	// NTP header is 48 bytes; extension fields may follow (multiples of 4 bytes).
	if len(b) < 48 {
		return nil, common.ErrNoClue
	}
	if len(b)%4 != 0 {
		return nil, errNotNTP
	}

	liVnMode := b[0]
	vn := (liVnMode >> 3) & 0x07
	mode := liVnMode & 0x07

	// We sniff client requests (mode 3). VN is typically 3 or 4.
	if mode != 3 {
		return nil, errNotNTP
	}
	if vn < 1 || vn > 4 {
		return nil, errNotNTP
	}
	// Client requests generally use stratum 0.
	if b[1] != 0 {
		return nil, errNotNTP
	}

	return &SniffHeader{}, nil
}
