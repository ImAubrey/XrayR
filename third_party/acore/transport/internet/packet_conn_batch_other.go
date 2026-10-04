//go:build !linux
// +build !linux

package internet

import (
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
)

func (c *PacketConnWrapper) WriteBatch(payloads [][]byte, addrs []net.Addr) (int, error) {
	if len(payloads) == 0 {
		return 0, nil
	}
	if len(payloads) != len(addrs) {
		return 0, errors.New("invalid UDP write batch: payloads and addrs size mismatch")
	}
	for i := 0; i < len(payloads); i++ {
		if _, err := c.Conn.WriteTo(payloads[i], addrs[i]); err != nil {
			return i, err
		}
	}
	return len(payloads), nil
}
