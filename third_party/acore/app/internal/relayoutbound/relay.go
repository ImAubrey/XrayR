package relayoutbound

import (
	"context"
	"sync"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/net/cnc"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/signal/done"
	"github.com/ImAubrey/acore/transport"
)

// Listener is a lightweight in-memory net.Listener used by internal API components.
type Listener struct {
	buffer chan net.Conn
	done   *done.Instance
}

func NewListener(bufferSize int) *Listener {
	if bufferSize <= 0 {
		bufferSize = 1
	}
	return &Listener{
		buffer: make(chan net.Conn, bufferSize),
		done:   done.New(),
	}
}

func (l *Listener) Add(conn net.Conn) {
	select {
	case l.buffer <- conn:
	case <-l.done.Wait():
		conn.Close()
	default:
		conn.Close()
	}
}

// Accept implements net.Listener.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.done.Wait():
		return nil, errors.New("listen closed")
	case c := <-l.buffer:
		return c, nil
	}
}

// Close implements net.Listener.
func (l *Listener) Close() error {
	common.Must(l.done.Close())
L:
	for {
		select {
		case c := <-l.buffer:
			c.Close()
		default:
			break L
		}
	}
	return nil
}

// Addr implements net.Listener.
func (l *Listener) Addr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IP{0, 0, 0, 0},
		Port: 0,
	}
}

// Handler bridges proxy links to the in-memory listener.
type Handler struct {
	tag      string
	listener *Listener
	access   sync.RWMutex
	closed   bool
}

func NewHandler(tag string, listener *Listener) *Handler {
	return &Handler{
		tag:      tag,
		listener: listener,
	}
}

// Dispatch implements outbound.Handler.
func (h *Handler) Dispatch(_ context.Context, link *transport.Link) {
	h.access.RLock()
	if h.closed {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		h.access.RUnlock()
		return
	}

	closeSignal := done.New()
	conn := cnc.NewConnection(
		cnc.ConnectionInputMulti(link.Writer),
		cnc.ConnectionOutputMulti(link.Reader),
		cnc.ConnectionOnClose(closeSignal),
	)
	h.listener.Add(conn)
	h.access.RUnlock()
	<-closeSignal.Wait()
}

// Tag implements outbound.Handler.
func (h *Handler) Tag() string {
	return h.tag
}

// Start implements common.Runnable.
func (h *Handler) Start() error {
	h.access.Lock()
	h.closed = false
	h.access.Unlock()
	return nil
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	h.access.Lock()
	defer h.access.Unlock()
	h.closed = true
	return h.listener.Close()
}

// SenderSettings implements outbound.Handler.
func (*Handler) SenderSettings() *serial.TypedMessage {
	return nil
}

// ProxySettings implements outbound.Handler.
func (*Handler) ProxySettings() *serial.TypedMessage {
	return nil
}
