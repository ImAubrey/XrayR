package outbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/binary"
	stdnet "net"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"

	proxyman "github.com/ImAubrey/acore/app/proxyman/outbound"
	"github.com/ImAubrey/acore/app/reverse"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	xctx "github.com/ImAubrey/acore/common/ctx"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/mux"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/retry"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/common/signal"
	"github.com/ImAubrey/acore/common/task"
	"github.com/ImAubrey/acore/common/xudp"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/policy"
	"github.com/ImAubrey/acore/features/routing"
	"github.com/ImAubrey/acore/proxy"
	"github.com/ImAubrey/acore/proxy/vless"
	"github.com/ImAubrey/acore/proxy/vless/encoding"
	"github.com/ImAubrey/acore/proxy/vless/encryption"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/internet/reality"
	"github.com/ImAubrey/acore/transport/internet/stat"
	"github.com/ImAubrey/acore/transport/internet/tls"
	"github.com/ImAubrey/acore/transport/pipe"
	utls "github.com/refraction-networking/utls"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is an outbound connection handler for VLess protocol.
type Handler struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	cone          bool
	encryption    *encryption.ClientInstance
	reverse       *Reverse

	testpre           uint32
	initpre           sync.Once
	preDone           chan struct{}
	preWG             sync.WaitGroup
	preConns          chan *ConnExpire
	preConKeepEnabled bool
	preConKeep        time.Duration

	closeOnce sync.Once
	closeErr  error
}

type ConnExpire struct {
	Conn   stat.Connection
	Expire time.Time
}

type preReadConn struct {
	stat.Connection
	buf []byte
}

func (c *preReadConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Connection.Read(p)
}

func (c *preReadConn) NetConn() stdnet.Conn {
	return c.Connection
}

// isPreconnectUsable checks if a preconnected TCP conn is still alive.
// It treats any read error (except timeout) as unusable. If data is pending,
// it keeps the connection usable and preserves the data.
func isPreconnectUsable(conn stat.Connection) (stat.Connection, bool) {
	if conn == nil {
		return nil, false
	}
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		// Best effort: if we can't set deadline, keep the old behavior.
		return conn, true
	}
	defer conn.SetReadDeadline(time.Time{})

	var b [1]byte
	n, err := conn.Read(b[:])
	if n > 0 {
		return &preReadConn{Connection: conn, buf: b[:n]}, true
	}
	if err == nil {
		return conn, true
	}
	if ne, ok := err.(stdnet.Error); ok && ne.Timeout() {
		return conn, true
	}
	return conn, false
}

const defaultPreConKeep = 25 * time.Second
const defaultPreconnectWait = 5 * time.Second
const preconnectRetryDelay = 200 * time.Millisecond

func preconnectKeepaliveFromConfig(v int64) (time.Duration, bool) {
	if v < 0 {
		return 0, false
	}
	if v == 0 {
		return defaultPreConKeep, true
	}
	return time.Duration(v), true
}

func applyPreconnectKeepalive(conn stat.Connection, keepAlive time.Duration) {
	if conn == nil || keepAlive <= 0 {
		return
	}
	raw := stat.TryUnwrapStatsConn(conn)
	raw = unwrapNetConn(raw)
	tcpConn, ok := raw.(*stdnet.TCPConn)
	if !ok {
		return
	}
	_ = tcpConn.SetKeepAliveConfig(stdnet.KeepAliveConfig{
		Enable:   true,
		Idle:     keepAlive,
		Interval: keepAlive,
	})
}

func unwrapNetConn(conn stdnet.Conn) stdnet.Conn {
	for {
		switch c := conn.(type) {
		case interface{ NetConn() stdnet.Conn }:
			next := c.NetConn()
			if next == nil || next == conn {
				return conn
			}
			conn = next
			continue
		}
		return conn
	}
}

func preconnectBaseContext(ob *session.Outbound) context.Context {
	ctx := context.Background()
	if ob == nil {
		return ctx
	}
	obCopy := *ob
	return session.ContextWithOutbounds(ctx, []*session.Outbound{&obCopy})
}

func applyDestVlessRoute(request *protocol.RequestHeader, route net.Port, enabled bool) {
	if !enabled || request == nil || request.User == nil {
		return
	}
	account, ok := request.User.Account.(*vless.MemoryAccount)
	if !ok || account == nil || account.ID == nil {
		return
	}

	id := account.ID.UUID()
	binary.BigEndian.PutUint16(id[6:8], route.Value())

	accountCopy := *account
	accountCopy.ID = protocol.NewID(id)

	userCopy := *request.User
	userCopy.Account = &accountCopy
	request.User = &userCopy
}

func (h *Handler) preconnectWaitTimeout() time.Duration {
	if h == nil || h.policyManager == nil || h.server == nil || h.server.User == nil {
		return defaultPreconnectWait
	}
	wait := h.policyManager.ForLevel(h.server.User.Level).Timeouts.Handshake
	if wait <= 0 {
		return defaultPreconnectWait
	}
	return wait
}

// getPreconnection retrieves a valid pre-established connection from the pool.
// It discards expired connections and returns the first valid one.
func (h *Handler) getPreconnection(ctx context.Context, timeout time.Duration) (*ConnExpire, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var timer <-chan time.Time
	var t *time.Timer
	if timeout > 0 {
		t = time.NewTimer(timeout)
		timer = t.C
	}
	if t != nil {
		defer t.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer:
			return nil, errors.New("pre-connect timeout")
		case connTime := <-h.preConns:
			if connTime == nil {
				return nil, errors.New("closed handler")
			}
			if time.Now().Before(connTime.Expire) {
				if conn, ok := isPreconnectUsable(connTime.Conn); ok {
					connTime.Conn = conn
					return connTime, nil
				}
				connTime.Conn.Close()
				continue
			}
			connTime.Conn.Close()
		}
	}
}

// New creates a new VLess outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	if config.Vnext == nil {
		return nil, errors.New(`no vnext found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Vnext)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err).AtError()
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	a := handler.server.User.Account.(*vless.MemoryAccount)
	if a.Encryption != "" && a.Encryption != "none" {
		s := strings.Split(a.Encryption, ".")
		var nfsPKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		handler.encryption = &encryption.ClientInstance{}
		if err := handler.encryption.Init(nfsPKeysBytes, a.XorMode, a.Seconds, a.Padding); err != nil {
			return nil, errors.New("failed to use encryption").Base(err).AtError()
		}
	}

	if a.Reverse != nil {
		handler.reverse = &Reverse{
			tag:        a.Reverse.Tag,
			dispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
			ctx: session.ContextWithInbound(ctx, &session.Inbound{
				Tag:  a.Reverse.Tag,
				User: handler.server.User, // TODO: email
			}),
			handler: handler,
		}
		handler.reverse.monitorTask = &task.Periodic{
			Execute:  handler.reverse.monitor,
			Interval: time.Second * 2,
		}
		go func() {
			time.Sleep(2 * time.Second)
			handler.reverse.Start()
		}()
	}

	handler.testpre = a.Testpre
	handler.preConKeep, handler.preConKeepEnabled = preconnectKeepaliveFromConfig(a.PreConKeep)

	return handler, nil
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	h.closeOnce.Do(func() {
		if h.preDone != nil {
			close(h.preDone)
		}
		// Wait for preconnect workers to stop sending before closing the channel.
		h.preWG.Wait()
		if h.preConns != nil {
			close(h.preConns)
			for connTime := range h.preConns {
				if connTime != nil && connTime.Conn != nil {
					connTime.Conn.Close()
				}
			}
		}
		if h.reverse != nil {
			h.closeErr = h.reverse.Close()
		}
	})
	return h.closeErr
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() && ob.Target.Address.String() != "v1.rvs.cool" {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "vless"

	rec := h.server
	var conn stat.Connection

	if h.testpre > 0 && h.reverse == nil {
		baseCtx := preconnectBaseContext(ob)
		preconnectTimeout := h.preconnectWaitTimeout()
		h.initpre.Do(func() {
			h.preDone = make(chan struct{})
			h.preConns = make(chan *ConnExpire)
			for range h.testpre { // TODO: randomize
				h.preWG.Add(1)
				go func() {
					defer h.preWG.Done()
					preCtx := xctx.ContextWithID(baseCtx, session.NewID())
					for {
						select {
						case <-h.preDone:
							return
						default:
						}

						dialCtx := preCtx
						var cancel context.CancelFunc
						if preconnectTimeout > 0 {
							dialCtx, cancel = context.WithTimeout(preCtx, preconnectTimeout)
						}
						conn, err := dialer.Dial(dialCtx, rec.Destination)
						if cancel != nil {
							cancel()
						}
						if err != nil {
							errors.LogWarningInner(preCtx, err, "pre-connect failed")
							time.Sleep(preconnectRetryDelay)
							continue
						}
						if h.preConKeepEnabled {
							applyPreconnectKeepalive(conn, h.preConKeep)
						}
						connTime := &ConnExpire{Conn: conn, Expire: time.Now().Add(time.Minute * 2)} // TODO: customize & randomize
						select {
						case h.preConns <- connTime:
						case <-h.preDone:
							conn.Close()
							return
						}

						select {
						case <-h.preDone:
							return
						default:
						}
						time.Sleep(preconnectRetryDelay) // TODO: customize & randomize
					}
				}()
			}
		})
		connTime, err := h.getPreconnection(ctx, preconnectTimeout)
		if err != nil {
			errors.LogWarningInner(ctx, err, "pre-connect unavailable, fallback to direct dial")
		} else {
			errors.LogInfo(ctx, "using pre-connect for ", rec.Destination.NetAddr(), " expiring at ", connTime.Expire)
			conn = connTime.Conn
		}
	}

	if conn == nil {
		if err := retry.ExponentialBackoff(5, 200).On(func() error {
			var err error
			conn, err = dialer.Dial(ctx, rec.Destination)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return errors.New("failed to find an available destination").Base(err).AtWarning()
		}
	}
	defer conn.Close()

	ob.Conn = conn // for Vision's pre-connect

	iConn := stat.TryUnwrapStatsConn(conn)
	target := ob.Target
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination.NetAddr())

	if h.encryption != nil {
		var err error
		if conn, err = h.encryption.Handshake(conn); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	command := protocol.RequestCommandTCP
	if target.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if target.Address.Family().IsDomain() {
		switch target.Address.Domain() {
		case "v1.mux.cool":
			command = protocol.RequestCommandMux
		case "v1.rvs.cool":
			if target.Network != net.Network_Unknown {
				return errors.New("nice try baby").AtError()
			}
			command = protocol.RequestCommandRvs
		}
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    rec.User,
		Command: command,
		Address: target.Address,
		Port:    target.Port,
	}
	applyDestVlessRoute(request, ob.DestVlessRoute, ob.HasDestVlessRoute)

	account := request.User.Account.(*vless.MemoryAccount)

	requestAddons := &encoding.Addons{
		Flow: account.Flow,
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	allowUDP443 := false
	switch requestAddons.Flow {
	case vless.XRV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case vless.XRV:
		ob.CanSpliceCopy = 2
		switch request.Command {
		case protocol.RequestCommandUDP:
			if !allowUDP443 && request.Port == 443 {
				return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
			}
		case protocol.RequestCommandMux:
			fallthrough // let server break Mux connections that contain TCP requests
		case protocol.RequestCommandTCP, protocol.RequestCommandRvs:
			var t reflect.Type
			var p unsafe.Pointer
			typedConn := conn
			for {
				if sc, ok := typedConn.(*stat.CounterConnection); ok {
					typedConn = sc.Connection
					continue
				}
				break
			}
			if commonConn, ok := typedConn.(*encryption.CommonConn); ok {
				if _, ok := commonConn.Conn.(*encryption.XorConn); ok || !proxy.IsRAWTransportWithoutSecurity(iConn) {
					ob.CanSpliceCopy = 3 // full-random xorConn / non-RAW transport / another securityConn should not be penetrated
				}
				t = reflect.TypeOf(commonConn).Elem()
				p = unsafe.Pointer(commonConn)
			} else if tlsConn, ok := typedConn.(*tls.Conn); ok {
				t = reflect.TypeOf(tlsConn.Conn).Elem()
				p = unsafe.Pointer(tlsConn.Conn)
			} else if utlsConn, ok := typedConn.(*tls.UConn); ok {
				t = reflect.TypeOf(utlsConn.Conn).Elem()
				p = unsafe.Pointer(utlsConn.Conn)
			} else if realityConn, ok := typedConn.(*reality.UConn); ok {
				t = reflect.TypeOf(realityConn.Conn).Elem()
				p = unsafe.Pointer(realityConn.Conn)
			} else {
				errors.LogInfo(ctx, "XTLS unsupported conn type: iConn=", reflect.TypeOf(iConn), " conn=", reflect.TypeOf(conn), " typedConn=", reflect.TypeOf(typedConn))
				return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
			}
			i, _ := t.FieldByName("input")
			r, _ := t.FieldByName("rawInput")
			input = (*bytes.Reader)(unsafe.Add(p, i.Offset))
			rawInput = (*bytes.Buffer)(unsafe.Add(p, r.Offset))
		default:
			panic("unknown VLESS request command")
		}
	default:
		ob.CanSpliceCopy = 1
		switch request.Command {
		case protocol.RequestCommandTCP:
			if !proxy.IsRAWTransportWithoutSecurity(iConn) {
				ob.CanSpliceCopy = 3
			}
			if _, ok := conn.(*encryption.CommonConn); ok {
				ob.CanSpliceCopy = 3
			}
		default:
			ob.CanSpliceCopy = 3
		}
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)
	downlinkOnlyTimeout := proxy.AdaptHalfCloseTimeout(conn, sessionPolicy.Timeouts.DownlinkOnly)
	uplinkOnlyTimeout := proxy.AdaptHalfCloseTimeout(conn, sessionPolicy.Timeouts.UplinkOnly)
	spliceCapable := request.Command == protocol.RequestCommandTCP && proxy.IsRAWTransportWithoutSecurity(conn)

	clientReader := link.Reader // .(*pipe.Reader)
	clientWriter := link.Writer // .(*pipe.Writer)
	trafficState := proxy.NewTrafficState(account.ID.Bytes())
	if request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == vless.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
		request.Command = protocol.RequestCommandMux
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = net.Port(666)
	}

	postRequest := func() error {
		defer func() {
			if spliceCapable {
				proxy.MarkConntrackSpliceHalfClosed(ctx, downlinkOnlyTimeout)
			}
			timer.SetTimeout(downlinkOnlyTimeout)
		}()

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
			return errors.New("failed to encode request header").Base(err).AtWarning()
		}

		// default: serverWriter := bufferWriter
		serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob)
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			serverWriter = xudp.NewPacketWriter(serverWriter, target, xudp.GetGlobalID(ctx))
		}
		timeoutReader, ok := clientReader.(buf.TimeoutReader)
		if ok {
			multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err1 == nil {
				if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil {
					return err // ...
				}
			} else if err1 != buf.ErrReadTimeout {
				return err1
			} else if requestAddons.Flow == vless.XRV {
				mb := make(buf.MultiBuffer, 1)
				errors.LogInfo(ctx, "Insert padding with empty content to camouflage VLESS header ", mb.Len())
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err // ...
				}
			}
		} else {
			errors.LogDebug(ctx, "Reader is not timeout reader, will send out vless header separately from first payload")
		}
		// Flush; bufferWriter.WriteMultiBuffer now is bufferWriter.writer.WriteMultiBuffer
		if err := bufferWriter.SetBuffered(false); err != nil {
			return errors.New("failed to write A request payload").Base(err).AtWarning()
		}

		if requestAddons.Flow == vless.XRV {
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version).AtWarning()
				}
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, utlsConn.ConnectionState().Version).AtWarning()
				}
			}
		}

		// Try splice (uplink): after VLESS request header is written, uplink payload can be copied
		// directly from inbound.Conn to the outbound conn once all splice flags become ready.
		// This is especially useful for XTLS Vision, where the writer may switch to raw mode later.
		copyUplink := func() error {
			if request.Command != protocol.RequestCommandTCP {
				return buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
			}
			inbound := session.InboundFromContext(ctx)
			if inbound == nil || inbound.Conn == nil || inbound.CanSpliceCopy != 1 {
				return buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
			}

			type cachedMultiBufferReader interface {
				ReadCachedMultiBuffer() (buf.MultiBuffer, bool)
				UnderlyingReader() buf.TimeoutReader
			}

			// Only attempt splice when link.Reader isn't a pipe (e.g. sniffing/indirect paths).
			var rawReader buf.Reader
			var cached cachedMultiBufferReader
			var buffered *buf.BufferedReader
			switch r := clientReader.(type) {
			case *conntrack.CountingReader:
				rawReader = r.Reader
			case *buf.TimeoutWrapperReader:
				rawReader = r.Reader
			case cachedMultiBufferReader:
				cached = r
				rawReader = r.UnderlyingReader()
			case *buf.BufferedReader:
				buffered = r
				rawReader = r.Reader
			default:
				return buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
			}

			for {
				switch rr := rawReader.(type) {
				case *conntrack.CountingReader:
					rawReader = rr.Reader
					continue
				case *buf.TimeoutWrapperReader:
					if _, isPipe := rr.Reader.(*pipe.Reader); isPipe {
						return buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
					}
					if br, ok := rr.Reader.(*buf.BufferedReader); ok {
						buffered = br
					}
				case *pipe.Reader:
					return buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
				case *buf.BufferedReader:
					buffered = rr
				}
				break
			}

			// Flush any cached/buffered bytes before switching to direct conn reads.
			if cached != nil {
				for {
					mb, ok := cached.ReadCachedMultiBuffer()
					if !ok {
						break
					}
					if mb != nil && !mb.IsEmpty() {
						if err := serverWriter.WriteMultiBuffer(mb); err != nil {
							return err
						}
					}
				}
			}
			if buffered != nil && buffered.BufferedBytes() > 0 {
				mb, err := buffered.ReadMultiBuffer()
				if err != nil {
					return err
				}
				if mb != nil && !mb.IsEmpty() {
					if err := serverWriter.WriteMultiBuffer(mb); err != nil {
						return err
					}
				}
			}

			return proxy.CopyRawConnIfExist(ctx, inbound.Conn, conn, serverWriter, timer, inbound.Timer)
		}

		err := copyUplink()
		if err != nil {
			return errors.New("failed to transfer request payload").Base(err).AtInfo()
		}

		// Indicates the end of request payload.
		switch requestAddons.Flow {
		default:
		}
		return nil
	}

	getResponse := func() error {
		defer func() {
			if spliceCapable {
				proxy.MarkConntrackSpliceHalfClosed(ctx, uplinkOnlyTimeout)
			}
			timer.SetTimeout(uplinkOnlyTimeout)
		}()

		responseAddons, err := encoding.DecodeResponseHeader(conn, request)
		if err != nil {
			return errors.New("failed to decode response header").Base(err).AtInfo()
		}

		// default: serverReader := buf.NewReader(conn)
		serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
		if requestAddons.Flow == vless.XRV {
			serverReader = proxy.NewVisionReader(serverReader, trafficState, false, ctx, conn, input, rawInput, ob)
		}
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			if requestAddons.Flow == vless.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		if requestAddons.Flow == vless.XRV {
			err = encoding.XtlsRead(serverReader, clientWriter, timer, conn, trafficState, false, ctx)
		} else if request.Command == protocol.RequestCommandTCP && proxy.IsRAWTransportWithoutSecurity(conn) {
			var writeConn net.Conn
			var inTimer *signal.ActivityTimer
			if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
				writeConn = inbound.Conn
				inTimer = inbound.Timer
			}
			err = proxy.CopyRawConnIfExist(ctx, conn, writeConn, clientWriter, timer, inTimer)
		} else {
			// from serverReader.ReadMultiBuffer to clientWriter.WriteMultiBuffer
			err = buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
		}

		if err != nil {
			return errors.New("failed to transfer response payload").Base(err).AtInfo()
		}

		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

type Reverse struct {
	tag         string
	dispatcher  routing.Dispatcher
	ctx         context.Context
	handler     *Handler
	workers     []*reverse.BridgeWorker
	monitorTask *task.Periodic
}

func (r *Reverse) monitor() error {
	var activeWorkers []*reverse.BridgeWorker
	for _, w := range r.workers {
		if w.IsActive() {
			activeWorkers = append(activeWorkers, w)
		}
	}
	if len(activeWorkers) != len(r.workers) {
		r.workers = activeWorkers
	}

	var numConnections uint32
	var numWorker uint32
	for _, w := range r.workers {
		if w.IsActive() {
			numConnections += w.Connections()
			numWorker++
		}
	}
	if numWorker == 0 || numConnections/numWorker > 16 {
		reader1, writer1 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		reader2, writer2 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		link1 := &transport.Link{Reader: reader1, Writer: writer2}
		link2 := &transport.Link{Reader: reader2, Writer: writer1}
		w := &reverse.BridgeWorker{
			Tag:        r.tag,
			Dispatcher: r.dispatcher,
		}
		worker, err := mux.NewServerWorker(session.ContextWithIsReverseMux(r.ctx, true), w, link1)
		if err != nil {
			errors.LogWarningInner(r.ctx, err, "failed to create mux server worker")
			return nil
		}
		w.Worker = worker
		r.workers = append(r.workers, w)
		go func() {
			ctx := session.ContextWithOutbounds(r.ctx, []*session.Outbound{{
				Target: net.Destination{Address: net.DomainAddress("v1.rvs.cool")},
			}})
			r.handler.Process(ctx, link2, session.FullHandlerFromContext(ctx).(*proxyman.Handler))
			common.Interrupt(reader1)
			common.Interrupt(reader2)
		}()
	}
	return nil
}

func (r *Reverse) Start() error {
	return r.monitorTask.Start()
}

func (r *Reverse) Close() error {
	return r.monitorTask.Close()
}
