package axpath

import (
	"context"
	gotls "crypto/tls"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	cnet "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/internet/reality"
	"github.com/ImAubrey/acore/transport/internet/stat"
	"github.com/ImAubrey/acore/transport/internet/tls"
	goreality "github.com/xtls/reality"
)

type Listener struct {
	listener      cnet.Listener
	tlsConfig     *gotls.Config
	realityConfig *goreality.Config

	cfg *Config

	handler internet.ConnHandler

	sessionsMu sync.Mutex
	sessions   map[[16]byte]*session
}

// ListenAXPath creates a new Listener based on configurations.
func ListenAXPath(ctx context.Context, address cnet.Address, port cnet.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	l := &Listener{
		handler:  handler,
		cfg:      streamSettings.ProtocolSettings.(*Config),
		sessions: make(map[[16]byte]*session),
	}

	ln, err := internet.ListenSystem(ctx, &cnet.TCPAddr{
		IP:   address.IP(),
		Port: int(port),
	}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}
	l.listener = ln

	if tcfg := tls.ConfigFromStreamSettings(streamSettings); tcfg != nil {
		l.tlsConfig = tcfg.GetTLSConfig()
	}
	if rcfg := reality.ConfigFromStreamSettings(streamSettings); rcfg != nil {
		l.realityConfig = rcfg.GetREALITYConfig()
		go goreality.DetectPostHandshakeRecordsLens(l.realityConfig)
	}

	go l.acceptLoop(ctx, streamSettings)
	return l, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenAXPath))
}

func (l *Listener) acceptLoop(ctx context.Context, streamSettings *internet.MemoryStreamConfig) {
	for {
		c, err := l.listener.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				return
			}
			errors.LogWarningInner(ctx, err, "axpath: failed to accept")
			time.Sleep(200 * time.Millisecond)
			continue
		}

		go l.handleConn(ctx, c, streamSettings)
	}
}

func (l *Listener) handleConn(ctx context.Context, conn cnet.Conn, streamSettings *internet.MemoryStreamConfig) {
	// Transport security.
	if l.tlsConfig != nil {
		conn = tls.Server(conn, l.tlsConfig)
	} else if l.realityConfig != nil {
		c2, err := reality.Server(conn, l.realityConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		conn = c2
	}

	base := l.cfg
	psk := base.GetNormalizedPsk()

	ch, err := decodeHello(conn, psk)
	if err != nil {
		_ = conn.Close()
		return
	}
	if !ch.isClient() {
		_ = conn.Close()
		return
	}

	// Validate basic hello fields early.
	if ch.Subflows == 0 {
		_ = conn.Close()
		return
	}
	if ch.SubflowID >= ch.Subflows {
		_ = conn.Close()
		return
	}

	// Enforce server-side caps (if configured). These are transport-level resources.
	maxSubflows := int(base.GetSubflows())
	if maxSubflows <= 0 {
		maxSubflows = 16
	}
	if maxSubflows < 1 {
		maxSubflows = 1
	}
	if maxSubflows > 16 {
		maxSubflows = 16
	}
	if int(ch.Subflows) > maxSubflows {
		_ = conn.Close()
		return
	}

	maxChunkSize := int(base.GetChunkSize())
	if maxChunkSize <= 0 {
		maxChunkSize = 1024 * 1024
	}
	if maxChunkSize < 1024 {
		maxChunkSize = 1024
	}
	if maxChunkSize > 1024*1024 {
		maxChunkSize = 1024 * 1024
	}
	if int(ch.ChunkSize) > maxChunkSize {
		_ = conn.Close()
		return
	}

	maxAckMaskBits := int(base.GetAckMaskBits())
	if maxAckMaskBits <= 0 {
		maxAckMaskBits = 4096
	}
	if maxAckMaskBits < 8 {
		maxAckMaskBits = 8
	}
	if maxAckMaskBits > 4096 {
		maxAckMaskBits = 4096
	}
	maxAckMaskBits = (maxAckMaskBits / 8) * 8
	if maxAckMaskBits < 8 {
		maxAckMaskBits = 8
	}
	if int(ch.AckMaskBits) > maxAckMaskBits {
		_ = conn.Close()
		return
	}

	// Create / lookup session. The first subflow defines the per-session transport parameters.
	created := false

	l.sessionsMu.Lock()
	s, ok := l.sessions[ch.SessionID]
	if !ok {
		created = true
		sessCfg := &Config{
			Subflows:         uint32(ch.Subflows),
			ChunkSize:        ch.ChunkSize,
			AckMaskBits:      uint32(ch.AckMaskBits),
			MaxInflightBytes: base.MaxInflightBytes,
			MaxQueuePerFlow:  base.MaxQueuePerFlow,
			JoinTimeoutMs:    base.JoinTimeoutMs,
			ResumeTimeoutMs:  base.ResumeTimeoutMs,
			Reconnect:        base.Reconnect,
			Psk:              base.Psk,
		}

		s = newSession(ctx, sessCfg)
		s.role = roleServer
		s.sessionID = ch.SessionID
		s.epoch = ch.Epoch
		s.setOnClose(func() {
			l.sessionsMu.Lock()
			delete(l.sessions, ch.SessionID)
			l.sessionsMu.Unlock()
		})
		l.sessions[ch.SessionID] = s
	}
	l.sessionsMu.Unlock()

	// For existing sessions, require consistent parameters.
	if !created {
		if s.epoch != ch.Epoch ||
			s.subflows != int(ch.Subflows) ||
			s.chunkSize != int(ch.ChunkSize) ||
			s.ackMaskBits != int(ch.AckMaskBits) ||
			ch.SubflowID >= byte(s.subflows) {
			_ = conn.Close()
			return
		}
	}

	// Respond with server hello.
	flags := byte(0)
	if psk != "" {
		flags |= flagHasPSK
	}
	b, err := encodeHello(hello{
		Flags:       flags,
		SubflowID:   ch.SubflowID,
		Subflows:    ch.Subflows,
		SessionID:   ch.SessionID,
		Epoch:       ch.Epoch,
		ChunkSize:   ch.ChunkSize,
		AckMaskBits: ch.AckMaskBits,
	}, psk)
	if err != nil || writeAll(conn, b) != nil {
		_ = conn.Close()
		return
	}

	if err := s.attachSubflow(ch.SubflowID, conn); err != nil {
		_ = conn.Close()
		return
	}

	if created {
		// Deliver the logical connection once per session, after at least one
		// subflow has been attached so LocalAddr/RemoteAddr are available.
		go l.handler(stat.Connection(s))
	}
}

// Addr implements internet.Listener.Addr.
func (l *Listener) Addr() cnet.Addr { return l.listener.Addr() }

// Close implements internet.Listener.Close.
func (l *Listener) Close() error {
	_ = l.listener.Close()

	// Avoid deadlock: session.closeWithError may call onClose, which uses sessionsMu.
	var sessions []*session
	l.sessionsMu.Lock()
	for _, s := range l.sessions {
		sessions = append(sessions, s)
	}
	l.sessions = make(map[[16]byte]*session)
	l.sessionsMu.Unlock()

	for _, s := range sessions {
		s.closeWithErrorReason(io.EOF, "listener_close")
	}
	return nil
}
