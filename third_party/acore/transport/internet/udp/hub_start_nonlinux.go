//go:build !linux
// +build !linux

package udp

import (
	"context"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol/udp"
)

func clampOOBN(n int, oob []byte) int {
	if n <= 0 {
		return 0
	}
	if n > len(oob) {
		return len(oob)
	}
	return n
}

func (h *Hub) start() {
	c := h.cache
	defer close(c)
	defer func() {
		if r := recover(); r != nil {
			errors.LogError(context.Background(), "panic in UDP hub: ", r)
		}
	}()

	oobBytes := make([]byte, 256)

	for {
		buffer := buf.New()
		var noob int
		var addr *net.UDPAddr
		rawBytes := buffer.Extend(buf.Size)

		n, noob, _, addr, err := ReadUDPMsg(h.conn, rawBytes, oobBytes)
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to read UDP msg")
			buffer.Release()
			break
		}
		buffer.Resize(0, int32(n))

		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}

		payload := &udp.Packet{
			Payload: buffer,
			Source:  net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)),
		}
		if h.recvOrigDest {
			noob = clampOOBN(noob, oobBytes)
			if noob > 0 {
				payload.Target = RetrieveOriginalDest(oobBytes[:noob])
				if payload.Target.IsValid() {
					errors.LogDebug(context.Background(), "UDP original destination: ", payload.Target)
				} else {
					errors.LogInfo(context.Background(), "failed to read UDP original destination")
				}
			}
		}

		select {
		case c <- payload:
		default:
			buffer.Release()
			payload.Payload = nil
		}
	}
}
