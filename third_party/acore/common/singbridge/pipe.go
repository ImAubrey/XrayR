package singbridge

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/transport"
	"github.com/sagernet/sing/common/bufio"
)

func CopyConn(ctx context.Context, inboundConn net.Conn, link *transport.Link, serverConn net.Conn) error {
	conn := &PipeConnWrapper{
		W:    link.Writer,
		Conn: inboundConn,
	}
	if ir, ok := link.Reader.(io.Reader); ok {
		conn.R = ir
	} else {
		conn.R = &buf.BufferedReader{Reader: link.Reader}
	}
	return ReturnError(bufio.CopyConn(ctx, conn, serverConn))
}

type PipeConnWrapper struct {
	R io.Reader
	W buf.Writer
	net.Conn

	closeOnce sync.Once
}

func (w *PipeConnWrapper) Close() error {
	w.closeOnce.Do(func() {
		// Unblock pending I/O first, then close the writer to signal upstream.
		_ = common.Interrupt(w.R)
		_ = common.Interrupt(w.W)
		_ = common.Close(w.W)
		_ = common.Close(w.Conn)
	})
	return nil
}

func (w *PipeConnWrapper) Read(b []byte) (n int, err error) {
	return w.R.Read(b)
}

func (w *PipeConnWrapper) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	n = len(p)
	mb := make(buf.MultiBuffer, 0, (len(p)+buf.Size-1)/buf.Size)
	for len(p) > 0 {
		buffer := buf.New()
		chunk := len(p)
		if chunk > buf.Size {
			chunk = buf.Size
		}
		_, _ = buffer.Write(p[:chunk])
		p = p[chunk:]
		mb = append(mb, buffer)
	}

	err = w.W.WriteMultiBuffer(mb)
	if err != nil {
		buf.ReleaseMulti(mb)
		return 0, err
	}
	return n, nil
}
