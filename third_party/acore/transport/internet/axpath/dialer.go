package axpath

import (
	"context"
	gotls "crypto/tls"
	stdErrors "errors"
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

func Dial(ctx context.Context, dest cnet.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	cfg := streamSettings.ProtocolSettings.(*Config)
	s := newSession(ctx, cfg)
	s.role = roleClient

	errors.LogInfo(ctx, "axpath: dialing axpath to ", dest, " subflows=", s.subflows)

	ready := make(chan error, s.subflows)
	for i := 0; i < s.subflows; i++ {
		id := byte(i)
		go func() {
			ready <- dialAndAttachSubflow(s.ctx, s, dest, streamSettings, id)
		}()
	}

	timeout := time.NewTimer(s.joinTimeout)
	defer timeout.Stop()

	var firstErr error
	for i := 0; i < s.subflows; i++ {
		select {
		case <-ctx.Done():
			s.closeWithErrorReason(ctx.Err(), "dial_ctx_done")
			return nil, ctx.Err()
		case <-timeout.C:
			s.closeWithErrorReason(context.DeadlineExceeded, "dial_join_timeout")
			if firstErr != nil {
				return nil, firstErr
			}
			return nil, context.DeadlineExceeded
		case err := <-ready:
			if err == nil {
				go clientMaintainSubflows(s.ctx, s, dest, streamSettings)
				return stat.Connection(s), nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	s.closeWithErrorReason(firstErr, "dial_no_subflows")
	if firstErr == nil {
		firstErr = stdErrors.New("axpath: no subflows established")
	}
	return nil, firstErr
}

func clientMaintainSubflows(ctx context.Context, s *session, dest cnet.Destination, streamSettings *internet.MemoryStreamConfig) {
	if s == nil || !s.reconnectSubflows {
		return
	}

	backoff := 200 * time.Millisecond
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var missing []byte
		s.flowsMu.RLock()
		for i := 0; i < s.subflows; i++ {
			id := byte(i)
			if f := s.flows[id]; f == nil || f.isClosed() {
				missing = append(missing, id)
			}
		}
		s.flowsMu.RUnlock()

		for _, id := range missing {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = dialAndAttachSubflow(ctx, s, dest, streamSettings, id)
			time.Sleep(backoff)
		}
	}
}

func dialAndAttachSubflow(ctx context.Context, s *session, dest cnet.Destination, streamSettings *internet.MemoryStreamConfig, id byte) error {
	if s != nil {
		if !s.beginDialing(id) {
			return stdErrors.New("axpath: dial already in progress")
		}
		defer s.endDialing(id)
	}

	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return err
	}

	conn2, err := wrapClientSecurity(ctx, conn, dest, streamSettings)
	if err != nil {
		_ = conn.Close()
		return err
	}

	if err := clientHello(conn2, s, id, s.epoch); err != nil {
		_ = conn2.Close()
		return err
	}

	if err := s.attachSubflow(id, conn2); err != nil {
		_ = conn2.Close()
		return err
	}

	return nil
}

func wrapClientSecurity(ctx context.Context, c cnet.Conn, dest cnet.Destination, streamSettings *internet.MemoryStreamConfig) (cnet.Conn, error) {
	if tcfg := tls.ConfigFromStreamSettings(streamSettings); tcfg != nil {
		tlsConfig := tcfg.GetTLSConfig(tls.WithDestination(dest))
		var err error
		if fp := tls.GetFingerprint(tcfg.Fingerprint); fp != nil {
			c = tls.UClient(c, tlsConfig, fp)
			err = c.(*tls.UConn).HandshakeContext(ctx)
		} else {
			c = tls.Client(c, tlsConfig)
			err = c.(*tls.Conn).HandshakeContext(ctx)
		}
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}

	if rcfg := reality.ConfigFromStreamSettings(streamSettings); rcfg != nil {
		c2, err := reality.UClient(c, rcfg, ctx, dest)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		return c2, nil
	}

	return c, nil
}

func clientHello(conn cnet.Conn, s *session, id byte, epoch uint32) error {
	flags := byte(flagRoleClient)
	if s.psk != "" {
		flags |= flagHasPSK
	}
	b, err := encodeHello(hello{
		Flags:       flags,
		SubflowID:   id,
		Subflows:    byte(s.subflows),
		SessionID:   s.sessionID,
		Epoch:       epoch,
		ChunkSize:   uint32(s.chunkSize),
		AckMaskBits: uint16(s.ackMaskBits),
	}, s.psk)
	if err != nil {
		return err
	}

	if err := writeAll(conn, b); err != nil {
		return err
	}

	sh, err := decodeHello(conn, s.psk)
	if err != nil {
		return err
	}
	if sh.isClient() {
		return stdErrors.New("axpath: server hello claims client role")
	}
	if sh.SessionID != s.sessionID {
		return stdErrors.New("axpath: server hello session id mismatch")
	}
	if sh.Subflows != byte(s.subflows) {
		return stdErrors.New("axpath: server hello subflows mismatch")
	}
	if int(sh.ChunkSize) != s.chunkSize {
		return stdErrors.New("axpath: server hello chunk_size mismatch")
	}
	if int(sh.AckMaskBits) != s.ackMaskBits {
		return stdErrors.New("axpath: server hello ack_mask_bits mismatch")
	}
	return nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

// Ensure we don't accidentally depend on server-side tls types here.
var _ *gotls.Config
var _ *goreality.Config
