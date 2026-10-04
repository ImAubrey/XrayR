//go:build linux
// +build linux

package internet

import (
	"context"
	goerrors "errors"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/platform"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	udpGSOMaxSegments = 64
	udpGSODataLen     = 2
)

var (
	udpGSOMaxSizeValue int
	udpGSOMaxSizeOnce  sync.Once

	udpGSODisabled       atomic.Bool
	udpGSODisableLogOnce sync.Once
)

func (c *PacketConnWrapper) WriteBatch(payloads [][]byte, addrs []net.Addr) (int, error) {
	if len(payloads) == 0 {
		return 0, nil
	}
	if len(payloads) != len(addrs) {
		return 0, errors.New("invalid UDP write batch: payloads and addrs size mismatch")
	}
	if len(payloads) == 1 {
		if _, err := c.Conn.WriteTo(payloads[0], addrs[0]); err != nil {
			return 0, err
		}
		return 1, nil
	}

	if n, used, err := c.tryWriteBatchGSO(payloads, addrs); used {
		return n, err
	}

	if _, ok := c.Conn.(net.Conn); !ok {
		return writeBatchFallback(c.Conn, payloads, addrs)
	}

	if shouldWriteBatchOverIPv6(c.localAddr, addrs) {
		msgs := make([]ipv6.Message, len(payloads))
		for i := range msgs {
			msgs[i].Buffers = [][]byte{payloads[i]}
			msgs[i].Addr = addrs[i]
		}
		n, err := ipv6.NewPacketConn(c.Conn).WriteBatch(msgs, 0)
		n = clampWriteBatchN(n, len(payloads))
		if n == 0 {
			return writeBatchFallback(c.Conn, payloads, addrs)
		}
		return n, err
	}

	msgs := make([]ipv4.Message, len(payloads))
	for i := range msgs {
		msgs[i].Buffers = [][]byte{payloads[i]}
		msgs[i].Addr = addrs[i]
	}
	n, err := ipv4.NewPacketConn(c.Conn).WriteBatch(msgs, 0)
	n = clampWriteBatchN(n, len(payloads))
	if n == 0 {
		return writeBatchFallback(c.Conn, payloads, addrs)
	}
	return n, err
}

func getUDPGSOMaxSize() int {
	udpGSOMaxSizeOnce.Do(func() {
		maxSize := platform.NewEnvFlag(platform.UDPGSOMaxSize).GetValueAsInt(0xFFFF)
		if maxSize < 0 {
			maxSize = 0
		}
		if maxSize > 0xFFFF {
			maxSize = 0xFFFF
		}
		udpGSOMaxSizeValue = maxSize
	})
	return udpGSOMaxSizeValue
}

func (c *PacketConnWrapper) tryWriteBatchGSO(payloads [][]byte, addrs []net.Addr) (int, bool, error) {
	if udpGSODisabled.Load() {
		return 0, false, nil
	}
	maxSize := getUDPGSOMaxSize()
	if maxSize <= 0 || len(payloads) < 2 || len(payloads) > udpGSOMaxSegments {
		return 0, false, nil
	}

	udpConn, ok := c.Conn.(*net.UDPConn)
	if !ok || udpConn == nil {
		return 0, false, nil
	}

	dest, segmentSize, payload, ok := buildUDPGSOPayload(payloads, addrs, maxSize)
	if !ok {
		return 0, false, nil
	}

	n, err := writeUDPGSO(udpConn, payload, dest, segmentSize)
	if err != nil {
		if isUDPGSOUnsupported(err) {
			udpGSODisabled.Store(true)
			udpGSODisableLogOnce.Do(func() {
				errors.LogInfo(context.Background(), "UDP GSO is unavailable on this system; falling back to regular UDP batch sends")
			})
		}
		if n == 0 {
			// Fall back to regular UDP batch send path when nothing is sent.
			return 0, false, nil
		}
		return 0, true, err
	}
	if n != len(payload) {
		return 0, true, errors.New("unexpected UDP GSO partial send")
	}
	return len(payloads), true, nil
}

func buildUDPGSOPayload(payloads [][]byte, addrs []net.Addr, maxSize int) (*net.UDPAddr, int, []byte, bool) {
	if len(payloads) != len(addrs) || len(payloads) < 2 {
		return nil, 0, nil, false
	}

	dest, ok := addrs[0].(*net.UDPAddr)
	if !ok || dest == nil {
		return nil, 0, nil, false
	}

	segmentSize := len(payloads[0])
	if segmentSize <= 0 || segmentSize > maxSize || segmentSize > 0xFFFF {
		return nil, 0, nil, false
	}

	totalLen := 0
	for i, payload := range payloads {
		if !sameUDPAddr(dest, addrs[i]) || len(payload) == 0 {
			return nil, 0, nil, false
		}
		if i < len(payloads)-1 {
			if len(payload) != segmentSize {
				return nil, 0, nil, false
			}
		} else if len(payload) > segmentSize {
			return nil, 0, nil, false
		}
		totalLen += len(payload)
	}

	merged := make([]byte, totalLen)
	offset := 0
	for _, payload := range payloads {
		offset += copy(merged[offset:], payload)
	}
	if offset != totalLen {
		return nil, 0, nil, false
	}

	return dest, segmentSize, merged, true
}

func sameUDPAddr(dest *net.UDPAddr, addr net.Addr) bool {
	candidate, ok := addr.(*net.UDPAddr)
	if !ok || candidate == nil {
		return false
	}
	if dest.Port != candidate.Port || dest.Zone != candidate.Zone {
		return false
	}
	if dest.IP == nil || candidate.IP == nil {
		return dest.IP == nil && candidate.IP == nil
	}
	return dest.IP.Equal(candidate.IP)
}

func writeUDPGSO(conn *net.UDPConn, payload []byte, dest *net.UDPAddr, segmentSize int) (int, error) {
	oob := makeUDPGSOOOB(segmentSize)
	n, _, err := conn.WriteMsgUDP(payload, oob, dest)
	return n, err
}

func makeUDPGSOOOB(segmentSize int) []byte {
	oob := make([]byte, unix.CmsgSpace(udpGSODataLen))
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = unix.IPPROTO_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(udpGSODataLen))
	*(*uint16)(unsafe.Pointer(&oob[unix.CmsgLen(0)])) = uint16(segmentSize)
	return oob
}

func isUDPGSOUnsupported(err error) bool {
	return goerrors.Is(err, unix.ENOPROTOOPT) || goerrors.Is(err, unix.EOPNOTSUPP) || goerrors.Is(err, unix.ENOTSUP)
}

func shouldWriteBatchOverIPv6(localAddr net.Addr, addrs []net.Addr) bool {
	if udpAddr, ok := localAddr.(*net.UDPAddr); ok && udpAddr != nil && udpAddr.IP != nil {
		return udpAddr.IP.To4() == nil
	}
	if len(addrs) == 0 {
		return false
	}
	if udpAddr, ok := addrs[0].(*net.UDPAddr); ok && udpAddr != nil && udpAddr.IP != nil {
		return udpAddr.IP.To4() == nil
	}
	return false
}

func clampWriteBatchN(n int, size int) int {
	if n < 0 {
		return 0
	}
	if n > size {
		return size
	}
	return n
}

func writeBatchFallback(conn net.PacketConn, payloads [][]byte, addrs []net.Addr) (int, error) {
	for i := 0; i < len(payloads); i++ {
		if _, err := conn.WriteTo(payloads[i], addrs[i]); err != nil {
			return i, err
		}
	}
	return len(payloads), nil
}
