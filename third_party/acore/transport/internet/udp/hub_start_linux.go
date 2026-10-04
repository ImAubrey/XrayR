//go:build linux
// +build linux

package udp

import (
	"context"
	goerrors "errors"
	"syscall"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol/udp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	udpBatchSizeDefault = 32
	udpOOBSize          = 256
)

func isIPv6Listener(conn *net.UDPConn) bool {
	laddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || laddr == nil {
		return false
	}
	if laddr.IP == nil {
		return false
	}
	// Treat dual-stack IPv6 (e.g. [::]:port) as IPv6.
	return laddr.IP.To4() == nil && len(laddr.IP) == net.IPv6len
}

func clampBatchN(n, batchSize int) int {
	if n < 0 {
		return 0
	}
	if n > batchSize {
		return batchSize
	}
	return n
}

func clampOOBN(n int, oob []byte) int {
	if n <= 0 {
		return 0
	}
	if n > len(oob) {
		return len(oob)
	}
	return n
}

func (h *Hub) startSingle(c chan *udp.Packet, bg context.Context) {
	oobBytes := make([]byte, udpOOBSize)

	for {
		buffer := buf.New()
		rawBytes := buffer.Extend(buf.Size)

		n, noob, _, addr, err := ReadUDPMsg(h.conn, rawBytes, oobBytes)
		if err != nil {
			errors.LogInfoInner(bg, err, "failed to read UDP msg")
			buffer.Release()
			return
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
					errors.LogDebug(bg, "UDP original destination: ", payload.Target)
				} else {
					errors.LogInfo(bg, "failed to read UDP original destination")
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

func (h *Hub) start() {
	c := h.cache
	defer close(c)
	defer func() {
		if r := recover(); r != nil {
			errors.LogError(context.Background(), "panic in UDP hub: ", r)
		}
	}()

	batchSize := udpBatchSizeDefault
	if h.capacity > 0 && h.capacity < batchSize {
		batchSize = h.capacity
	}
	if batchSize < 1 {
		batchSize = 1
	}

	payloadBufs := make([][]byte, batchSize)
	buffers := make([]*buf.Buffer, batchSize)

	bg := context.Background()

	if isIPv6Listener(h.conn) {
		pc := ipv6.NewPacketConn(h.conn)
		msgs := make([]ipv6.Message, batchSize)
		for i := range msgs {
			msgs[i].Buffers = payloadBufs[i : i+1]
			if h.recvOrigDest {
				msgs[i].OOB = make([]byte, udpOOBSize)
			}
		}

		for {
			for i := 0; i < batchSize; i++ {
				b := buf.New()
				buffers[i] = b
				payloadBufs[i] = b.Extend(buf.Size)
				msgs[i].Addr = nil
				msgs[i].N = 0
				msgs[i].NN = 0
				msgs[i].Flags = 0
			}

			n, err := pc.ReadBatch(msgs, 0)
			n = clampBatchN(n, batchSize)

			for i := 0; i < batchSize; i++ {
				if i >= n {
					buffers[i].Release()
					buffers[i] = nil
				}
			}

			for i := 0; i < n; i++ {
				msg := msgs[i]
				b := buffers[i]
				buffers[i] = nil

				b.Resize(0, int32(msg.N))
				if b.IsEmpty() {
					b.Release()
					continue
				}

				addr, ok := msg.Addr.(*net.UDPAddr)
				if !ok || addr == nil {
					b.Release()
					continue
				}

				packet := &udp.Packet{
					Payload: b,
					Source:  net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)),
				}
				if h.recvOrigDest {
					nn := clampOOBN(msg.NN, msg.OOB)
					if nn > 0 {
						packet.Target = RetrieveOriginalDest(msg.OOB[:nn])
						if packet.Target.IsValid() {
							errors.LogDebug(bg, "UDP original destination: ", packet.Target)
						} else {
							errors.LogInfo(bg, "failed to read UDP original destination")
						}
					}
				}

				select {
				case c <- packet:
				default:
					b.Release()
					packet.Payload = nil
				}
			}

			if err != nil {
				if goerrors.Is(err, syscall.EINTR) {
					continue
				}
				// Batch read is not available or failed; fall back to single-packet read to keep service running.
				errors.LogInfoInner(bg, err, "UDP batch read failed; falling back to single read")
				h.startSingle(c, bg)
				return
			}
		}
		return
	}

	pc := ipv4.NewPacketConn(h.conn)
	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = payloadBufs[i : i+1]
		if h.recvOrigDest {
			msgs[i].OOB = make([]byte, udpOOBSize)
		}
	}

	for {
		for i := 0; i < batchSize; i++ {
			b := buf.New()
			buffers[i] = b
			payloadBufs[i] = b.Extend(buf.Size)
			msgs[i].Addr = nil
			msgs[i].N = 0
			msgs[i].NN = 0
			msgs[i].Flags = 0
		}

		n, err := pc.ReadBatch(msgs, 0)
		n = clampBatchN(n, batchSize)

		for i := 0; i < batchSize; i++ {
			if i >= n {
				buffers[i].Release()
				buffers[i] = nil
			}
		}

		for i := 0; i < n; i++ {
			msg := msgs[i]
			b := buffers[i]
			buffers[i] = nil

			b.Resize(0, int32(msg.N))
			if b.IsEmpty() {
				b.Release()
				continue
			}

			addr, ok := msg.Addr.(*net.UDPAddr)
			if !ok || addr == nil {
				b.Release()
				continue
			}

			packet := &udp.Packet{
				Payload: b,
				Source:  net.UDPDestination(net.IPAddress(addr.IP), net.Port(addr.Port)),
			}
			if h.recvOrigDest {
				nn := clampOOBN(msg.NN, msg.OOB)
				if nn > 0 {
					packet.Target = RetrieveOriginalDest(msg.OOB[:nn])
					if packet.Target.IsValid() {
						errors.LogDebug(bg, "UDP original destination: ", packet.Target)
					} else {
						errors.LogInfo(bg, "failed to read UDP original destination")
					}
				}
			}

			select {
			case c <- packet:
			default:
				b.Release()
				packet.Payload = nil
			}
		}

		if err != nil {
			if goerrors.Is(err, syscall.EINTR) {
				continue
			}
			// Batch read is not available or failed; fall back to single-packet read to keep service running.
			errors.LogInfoInner(bg, err, "UDP batch read failed; falling back to single read")
			h.startSingle(c, bg)
			return
		}
	}
}
