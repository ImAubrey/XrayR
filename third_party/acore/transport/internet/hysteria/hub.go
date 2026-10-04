package hysteria

import (
	"context"
	gotls "crypto/tls"
	"encoding/binary"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/proxy/hysteria/account"
	hyCtx "github.com/ImAubrey/acore/proxy/hysteria/ctx"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/internet/tls"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	internalObfsKey         = "x-acore-hysteria-obfs"
	internalObfsPasswordKey = "x-acore-hysteria-obfs-password"
)

type udpSessionManagerServer struct {
	conn           *quic.Conn
	m              map[uint32]*InterUdpConn
	addConn        internet.ConnHandler
	stopCh         chan struct{}
	udpIdleTimeout time.Duration
	mutex          sync.RWMutex

	user *protocol.MemoryUser
}

func (m *udpSessionManagerServer) close(udpConn *InterUdpConn) {
	if !udpConn.closed {
		udpConn.closed = true
		close(udpConn.ch)
		delete(m.m, udpConn.id)
	}
}

func (m *udpSessionManagerServer) clean() {
	ticker := time.NewTicker(idleCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.mutex.RLock()
			now := time.Now()
			timeoutConn := make([]*InterUdpConn, 0, len(m.m))
			for _, udpConn := range m.m {
				if now.Sub(udpConn.GetLast()) > m.udpIdleTimeout {
					timeoutConn = append(timeoutConn, udpConn)
				}
			}
			m.mutex.RUnlock()

			for _, udpConn := range timeoutConn {
				m.mutex.Lock()
				m.close(udpConn)
				m.mutex.Unlock()
			}
		case <-m.stopCh:
			return
		}
	}
}

func (m *udpSessionManagerServer) run() {
	for {
		d, err := m.conn.ReceiveDatagram(context.Background())
		if err != nil {
			break
		}

		if len(d) < 4 {
			continue
		}
		id := binary.BigEndian.Uint32(d[:4])

		m.feed(id, d)
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	close(m.stopCh)

	for _, udpConn := range m.m {
		m.close(udpConn)
	}
}

func (m *udpSessionManagerServer) feed(id uint32, d []byte) {
	m.mutex.RLock()
	udpConn, ok := m.m[id]
	if ok {
		select {
		case udpConn.ch <- d:
		default:
		}
		m.mutex.RUnlock()
		return
	}
	m.mutex.RUnlock()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	udpConn, ok = m.m[id]
	if !ok {
		udpConn = &InterUdpConn{
			conn:   m.conn,
			local:  m.conn.LocalAddr(),
			remote: m.conn.RemoteAddr(),
			id:     id,
			ch:     make(chan []byte, udpMessageChanSize),
			last:   time.Now(),
			user:   m.user,
		}
		udpConn.closeFunc = func() {
			m.mutex.Lock()
			m.close(udpConn)
			m.mutex.Unlock()
		}
		m.m[id] = udpConn
		m.addConn(udpConn)
	}

	select {
	case udpConn.ch <- d:
	default:
	}
}

type httpHandler struct {
	ctx     context.Context
	conn    *quic.Conn
	addConn internet.ConnHandler

	config      *Config
	validator   *account.Validator
	masqHandler http.Handler

	auth  bool
	mutex sync.Mutex
	user  *protocol.MemoryUser
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == URLHost && r.URL.Path == URLPath {
		h.mutex.Lock()
		defer h.mutex.Unlock()

		if h.auth {
			w.Header().Set(ResponseHeaderUDPEnabled, strconv.FormatBool(hyCtx.RequireDatagramFromContext(h.ctx)))
			w.Header().Set(CommonHeaderCCRX, "0")
			w.Header().Set(CommonHeaderPadding, authResponsePadding.String())
			w.WriteHeader(StatusAuthOK)
			return
		}

		auth := r.Header.Get(RequestHeaderAuth)

		var user *protocol.MemoryUser
		var ok bool
		if h.validator != nil && h.validator.GetCount() > 0 {
			user = h.validator.Get(auth)
		} else if h.config.Auth != "" {
			ok = auth == h.config.Auth
		}

		if user != nil || ok {
			h.auth = true
			h.user = user

			if hyCtx.RequireDatagramFromContext(h.ctx) {
				udpSM := &udpSessionManagerServer{
					conn:           h.conn,
					m:              make(map[uint32]*InterUdpConn),
					addConn:        h.addConn,
					stopCh:         make(chan struct{}),
					udpIdleTimeout: time.Duration(h.config.UdpIdleTimeout) * time.Second,
					user:           h.user,
				}
				go udpSM.clean()
				go udpSM.run()
			}

			w.Header().Set(ResponseHeaderUDPEnabled, strconv.FormatBool(hyCtx.RequireDatagramFromContext(h.ctx)))
			w.Header().Set(CommonHeaderCCRX, "0")
			w.Header().Set(CommonHeaderPadding, authResponsePadding.String())
			w.WriteHeader(StatusAuthOK)
			return
		}
	}

	h.masqHandler.ServeHTTP(w, r)
}

func (h *httpHandler) StreamHijacker(ft http3.FrameType, _ quic.ConnectionTracingID, stream *quic.Stream, err error) (bool, error) {
	if err != nil || !h.auth {
		return false, nil
	}

	switch ft {
	case http3.FrameType(FrameTypeTCPRequest):
		h.addConn(&interConn{
			stream: stream,
			local:  h.conn.LocalAddr(),
			remote: h.conn.RemoteAddr(),
			user:   h.user,
		})
		return true, nil
	default:
		return false, nil
	}
}

type Listener struct {
	ctx      context.Context
	pktConn  net.PacketConn
	listener *quic.Listener
	addConn  internet.ConnHandler

	config      *Config
	validator   *account.Validator
	masqHandler http.Handler
}

func (l *Listener) handleClient(conn *quic.Conn) {
	handler := &httpHandler{
		ctx:         l.ctx,
		conn:        conn,
		addConn:     l.addConn,
		config:      l.config,
		validator:   l.validator,
		masqHandler: l.masqHandler,
	}
	h3 := http3.Server{
		Handler:        handler,
		StreamHijacker: handler.StreamHijacker,
	}
	err := h3.ServeQUICConn(conn)
	_ = conn.CloseWithError(closeErrCodeOK, "")
	errors.LogDebug(context.Background(), conn.RemoteAddr(), " disconnected with err ", err)
}

func (l *Listener) keepAccepting() {
	for {
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to accept QUIC connection")
			break
		}
		go l.handleClient(conn)
	}
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *Listener) Close() error {
	err := l.listener.Close()
	_ = l.pktConn.Close()
	return err
}

func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("address is domain")
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}

	config := streamSettings.ProtocolSettings.(*Config)
	validator := hyCtx.ValidatorFromContext(ctx)
	if config.Auth == "" && validator == nil {
		return nil, errors.New("validator is nil")
	}

	obfs, obfsPassword := extractInternalObfs(config)
	masqHandler, err := buildMasqueradeHandler(config)
	if err != nil {
		return nil, err
	}

	raw, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	pktConn := net.PacketConn(raw)
	if obfs != "" {
		pktConn, err = wrapObfsPacketConn(pktConn, obfs, obfsPassword)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     8388608,
		MaxStreamReceiveWindow:         8388608,
		InitialConnectionReceiveWindow: 8388608 * 5 / 2,
		MaxConnectionReceiveWindow:     8388608 * 5 / 2,
		MaxIdleTimeout:                 30 * time.Second,
		MaxIncomingStreams:             1024,
		EnableDatagrams:                true,
	}

	qListener, err := quic.Listen(pktConn, tlsConfig.GetTLSConfig(), quicConfig)
	if err != nil {
		_ = pktConn.Close()
		return nil, err
	}

	listener := &Listener{
		ctx:         ctx,
		pktConn:     pktConn,
		listener:    qListener,
		addConn:     handler,
		config:      config,
		validator:   validator,
		masqHandler: masqHandler,
	}

	go listener.keepAccepting()

	return listener, nil
}

func extractInternalObfs(config *Config) (string, string) {
	if config.MasqStringHeaders == nil {
		return "", ""
	}
	obfs := config.MasqStringHeaders[internalObfsKey]
	password := config.MasqStringHeaders[internalObfsPasswordKey]
	delete(config.MasqStringHeaders, internalObfsKey)
	delete(config.MasqStringHeaders, internalObfsPasswordKey)
	return strings.ToLower(obfs), password
}

func buildMasqueradeHandler(config *Config) (http.Handler, error) {
	switch strings.ToLower(config.MasqType) {
	case "", "404":
		return http.NotFoundHandler(), nil
	case "file":
		return http.FileServer(http.Dir(config.MasqFile)), nil
	case "proxy":
		u, err := url.Parse(config.MasqUrl)
		if err != nil {
			return nil, err
		}
		transport := http.DefaultTransport.(*http.Transport)
		if config.MasqUrlInsecure {
			transport = transport.Clone()
			transport.TLSClientConfig = &gotls.Config{
				InsecureSkipVerify: true,
			}
		}
		return &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(u)
				if !config.MasqUrlRewriteHost {
					pr.Out.Host = pr.In.Host
				}
			},
			Transport: transport,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.WriteHeader(http.StatusBadGateway)
			},
		}, nil
	case "string":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range config.MasqStringHeaders {
				w.Header().Set(k, v)
			}
			if config.MasqStringStatusCode != 0 {
				w.WriteHeader(int(config.MasqStringStatusCode))
			} else {
				w.WriteHeader(http.StatusOK)
			}
			_, _ = w.Write([]byte(config.MasqString))
		}), nil
	default:
		return nil, errors.New("unknown masq type")
	}
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
