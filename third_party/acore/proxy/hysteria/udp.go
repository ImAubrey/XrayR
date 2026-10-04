package hysteria

import (
	"context"
	go_errors "errors"
	"io"
	"math/rand"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/quic-go/quic-go"
)

type UDPWriter struct {
	Writer io.Writer
	buf    []byte
	addr   string
}

func (w *UDPWriter) sendMsg(msg *UDPMessage) error {
	msgN := msg.Serialize(w.buf)
	if msgN < 0 {
		return nil
	}
	_, err := w.Writer.Write(w.buf[:msgN])
	return err
}

func (w *UDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}

		addr := w.addr
		if b.UDP != nil {
			addr = b.UDP.NetAddr()
		}

		msg := &UDPMessage{
			SessionID: 0,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      addr,
			Data:      b.Bytes(),
		}

		err := w.sendMsg(msg)
		var errTooLarge *quic.DatagramTooLargeError
		if go_errors.As(err, &errTooLarge) {
			msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
			fMsgs := FragUDPMessage(msg, int(errTooLarge.MaxDatagramPayloadSize))
			for _, fMsg := range fMsgs {
				err := w.sendMsg(&fMsg)
				if err != nil {
					b.Release()
					buf.ReleaseMulti(mb)
					return err
				}
			}
		} else if err != nil {
			b.Release()
			buf.ReleaseMulti(mb)
			return err
		}

		b.Release()
	}

	return nil
}

type UDPReader struct {
	Reader    io.Reader
	buf       []byte
	df        *Defragger
	firstMsg  *UDPMessage
	firstDest *net.Destination
}

func (r *UDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.firstMsg != nil {
		buffer := buf.New()
		_, err := buffer.Write(r.firstMsg.Data)
		if err != nil {
			return nil, err
		}
		buffer.UDP = r.firstDest

		r.firstMsg = nil
		r.firstDest = nil

		return buf.MultiBuffer{buffer}, nil
	}
	for {
		n, err := r.Reader.Read(r.buf)
		if err != nil {
			return nil, err
		}

		msg, err := ParseUDPMessage(r.buf[:n])
		if err != nil {
			continue
		}

		dfMsg := r.df.Feed(msg)
		if dfMsg == nil {
			continue
		}

		dest, err := net.ParseDestination("udp:" + dfMsg.Addr)
		if err != nil {
			errors.LogDebug(context.Background(), dfMsg.Addr, " ParseDestination err ", err)
			continue
		}

		buffer := buf.New()
		if _, err := buffer.Write(dfMsg.Data); err != nil {
			return nil, err
		}

		buffer.UDP = &dest

		return buf.MultiBuffer{buffer}, nil
	}
}
