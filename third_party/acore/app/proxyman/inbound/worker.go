package inbound

import (
	"container/heap"
	"context"
	"sync"
	"time"

	"github.com/ImAubrey/acore/app/proxyman"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	c "github.com/ImAubrey/acore/common/ctx"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/common/signal/done"
	"github.com/ImAubrey/acore/features/routing"
	"github.com/ImAubrey/acore/features/stats"
	"github.com/ImAubrey/acore/proxy"
	"github.com/ImAubrey/acore/proxy/hysteria/account"
	hyCtx "github.com/ImAubrey/acore/proxy/hysteria/ctx"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/internet/stat"
	"github.com/ImAubrey/acore/transport/internet/tcp"
	"github.com/ImAubrey/acore/transport/internet/udp"
	"github.com/ImAubrey/acore/transport/pipe"
)

type worker interface {
	Start() error
	Close() error
	Port() net.Port
	Proxy() proxy.Inbound
}

type tcpWorker struct {
	address         net.Address
	port            net.Port
	proxy           proxy.Inbound
	stream          *internet.MemoryStreamConfig
	recvOrigDest    bool
	tag             string
	dispatcher      routing.Dispatcher
	sniffingConfig  *proxyman.SniffingConfig
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter

	hub internet.Listener

	ctx context.Context
}

func getTProxyType(s *internet.MemoryStreamConfig) internet.SocketConfig_TProxyMode {
	if s == nil || s.SocketSettings == nil {
		return internet.SocketConfig_Off
	}
	return s.SocketSettings.Tproxy
}

func isTransparentInbound(s *internet.MemoryStreamConfig) bool {
	switch getTProxyType(s) {
	case internet.SocketConfig_TProxy, internet.SocketConfig_Redirect:
		return true
	default:
		return false
	}
}

func (w *tcpWorker) callback(conn stat.Connection) {
	ctx, cancel := context.WithCancel(w.ctx)
	sid := session.NewID()
	ctx = c.ContextWithID(ctx, sid)

	outbounds := []*session.Outbound{{}}
	if w.recvOrigDest {
		var dest net.Destination
		switch getTProxyType(w.stream) {
		case internet.SocketConfig_Redirect:
			d, err := tcp.GetOriginalDestination(conn)
			if err != nil {
				errors.LogInfoInner(ctx, err, "failed to get original destination")
			} else {
				dest = d
			}
		case internet.SocketConfig_TProxy:
			dest = net.DestinationFromAddr(conn.LocalAddr())
		}

		if dest.IsValid() {
			// Check if try to connect to this inbound itself (can cause loopback)
			var isLoopBack bool
			if w.address == net.AnyIP || w.address == net.AnyIPv6 {
				if dest.Port.Value() == w.port.Value() && IsLocal(dest.Address.IP()) {
					isLoopBack = true
				}
			} else {
				if w.hub.Addr().String() == dest.NetAddr() {
					isLoopBack = true
				}
			}
			if isLoopBack {
				cancel()
				conn.Close()
				errors.LogError(ctx, errors.New("loopback connection detected"))
				return
			}
			outbounds[0].Target = dest
		}
	}
	ctx = session.ContextWithOutbounds(ctx, outbounds)

	if w.uplinkCounter != nil || w.downlinkCounter != nil {
		conn = &stat.CounterConnection{
			Connection:   conn,
			ReadCounter:  w.uplinkCounter,
			WriteCounter: w.downlinkCounter,
		}
	}
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source:      net.DestinationFromAddr(conn.RemoteAddr()),
		Local:       net.DestinationFromAddr(conn.LocalAddr()),
		Gateway:     net.TCPDestination(w.address, w.port),
		Transparent: isTransparentInbound(w.stream),
		Tag:         w.tag,
		Conn:        conn,
	})

	content := new(session.Content)
	if w.sniffingConfig != nil {
		content.SniffingRequest.Enabled = w.sniffingConfig.Enabled
		content.SniffingRequest.OverrideDestinationForProtocol = w.sniffingConfig.DestinationOverride
		content.SniffingRequest.ExcludeForDomain = w.sniffingConfig.DomainsExcluded
		content.SniffingRequest.MetadataOnly = w.sniffingConfig.MetadataOnly
		content.SniffingRequest.RouteOnly = w.sniffingConfig.RouteOnly
	}
	ctx = session.ContextWithContent(ctx, content)

	if err := w.proxy.Process(ctx, net.Network_TCP, conn, w.dispatcher); err != nil {
		errors.LogInfoInner(ctx, err, "connection ends")
	}
	cancel()
	conn.Close()
}

func (w *tcpWorker) Proxy() proxy.Inbound {
	return w.proxy
}

func (w *tcpWorker) Start() error {
	ctx := context.Background()

	type HysteriaInboundValidator interface{ HysteriaInboundValidator() *account.Validator }
	if v, ok := w.proxy.(HysteriaInboundValidator); ok {
		ctx = hyCtx.ContextWithRequireDatagram(ctx, true)
		ctx = hyCtx.ContextWithValidator(ctx, v.HysteriaInboundValidator())
	}

	hub, err := internet.ListenTCP(ctx, w.address, w.port, w.stream, func(conn stat.Connection) {
		go w.callback(conn)
	})
	if err != nil {
		return errors.New("failed to listen TCP on ", w.port).AtWarning().Base(err)
	}
	w.hub = hub
	return nil
}

func (w *tcpWorker) Close() error {
	var errs []interface{}
	if w.hub != nil {
		if err := common.Close(w.hub); err != nil {
			errs = append(errs, err)
		}
		if err := common.Close(w.proxy); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.New("failed to close all resources").Base(errors.New(serial.Concat(errs...)))
	}

	return nil
}

func (w *tcpWorker) Port() net.Port {
	return w.port
}

type udpConn struct {
	id         connID
	ctx        context.Context
	reader     buf.Reader
	writer     buf.Writer
	output     func([]byte) (int, error)
	remote     net.Addr
	local      net.Addr
	done       *done.Instance
	uplink     stats.Counter
	downlink   stats.Counter
	closeOnce  sync.Once
	cancel     context.CancelFunc
	onActivity func(replied bool)

	replied   bool
	deadline  time.Time
	heapIndex int
}

func (c *udpConn) updateActivity() {
	if c.onActivity != nil {
		c.onActivity(false)
	}
}

func (c *udpConn) markReplied() {
	if c.onActivity != nil {
		c.onActivity(true)
	}
}

// ReadMultiBuffer implements buf.Reader
func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := c.reader.ReadMultiBuffer()
	if err != nil {
		return nil, err
	}
	c.updateActivity()

	if c.uplink != nil {
		c.uplink.Add(int64(mb.Len()))
	}

	return mb, nil
}

func (c *udpConn) Read(buf []byte) (int, error) {
	panic("not implemented")
}

// Write implements io.Writer.
func (c *udpConn) Write(buf []byte) (int, error) {
	n, err := c.output(buf)
	if c.downlink != nil {
		c.downlink.Add(int64(n))
	}
	if err == nil {
		c.markReplied()
		c.updateActivity()
	}
	return n, err
}

func (c *udpConn) Close() error {
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		common.Must(c.done.Close())
		common.Must(common.Close(c.writer))
	})
	return nil
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *udpConn) LocalAddr() net.Addr {
	return c.local
}

func (*udpConn) SetDeadline(time.Time) error {
	return nil
}

func (*udpConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*udpConn) SetWriteDeadline(time.Time) error {
	return nil
}

type udpConnTimeoutHeap []*udpConn

func (h udpConnTimeoutHeap) Len() int { return len(h) }

func (h udpConnTimeoutHeap) Less(i, j int) bool {
	return h[i].deadline.Before(h[j].deadline)
}

func (h udpConnTimeoutHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex = i
	h[j].heapIndex = j
}

func (h *udpConnTimeoutHeap) Push(x interface{}) {
	conn := x.(*udpConn)
	conn.heapIndex = len(*h)
	*h = append(*h, conn)
}

func (h *udpConnTimeoutHeap) Pop() interface{} {
	old := *h
	n := len(old)
	conn := old[n-1]
	conn.heapIndex = -1
	*h = old[:n-1]
	return conn
}

type connID struct {
	src  net.Destination
	dest net.Destination
}

type udpWorker struct {
	sync.RWMutex

	proxy           proxy.Inbound
	hub             *udp.Hub
	address         net.Address
	port            net.Port
	tag             string
	stream          *internet.MemoryStreamConfig
	dispatcher      routing.Dispatcher
	sniffingConfig  *proxyman.SniffingConfig
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter

	activeConn map[connID]*udpConn

	timeoutHeap  udpConnTimeoutHeap
	timeoutWake  chan struct{}
	timeoutStop  chan struct{}
	timeoutWG    sync.WaitGroup
	unrepliedTTL time.Duration
	assuredTTL   time.Duration

	ctx  context.Context
	cone bool
}

const (
	udpUnrepliedTimeout = 30 * time.Second
	udpAssuredTimeout   = 120 * time.Second
)

func (w *udpWorker) unrepliedTimeout() time.Duration {
	if w.unrepliedTTL > 0 {
		return w.unrepliedTTL
	}
	return udpUnrepliedTimeout
}

func (w *udpWorker) assuredTimeout() time.Duration {
	if w.assuredTTL > 0 {
		return w.assuredTTL
	}
	return udpAssuredTimeout
}

func (w *udpWorker) signalTimeoutWakeLocked() {
	if w.timeoutWake == nil {
		return
	}
	select {
	case w.timeoutWake <- struct{}{}:
	default:
	}
}

func (w *udpWorker) addConnTimeoutLocked(conn *udpConn, now time.Time) {
	conn.replied = false
	conn.deadline = now.Add(w.unrepliedTimeout())
	conn.heapIndex = -1
	heap.Push(&w.timeoutHeap, conn)
	if conn.heapIndex == 0 {
		w.signalTimeoutWakeLocked()
	}
}

func (w *udpWorker) touchConnLocked(conn *udpConn, replied bool, now time.Time) {
	if conn.heapIndex < 0 || conn.done.Done() {
		return
	}
	if replied {
		conn.replied = true
	}
	if conn.replied {
		conn.deadline = now.Add(w.assuredTimeout())
	} else {
		conn.deadline = now.Add(w.unrepliedTimeout())
	}
	heap.Fix(&w.timeoutHeap, conn.heapIndex)
	if conn.heapIndex == 0 {
		w.signalTimeoutWakeLocked()
	}
}

func (w *udpWorker) removeConnTimeoutLocked(conn *udpConn) {
	if conn.heapIndex < 0 {
		return
	}
	wasTop := conn.heapIndex == 0
	heap.Remove(&w.timeoutHeap, conn.heapIndex)
	if wasTop {
		w.signalTimeoutWakeLocked()
	}
}

func (w *udpWorker) touchConn(conn *udpConn, replied bool) {
	w.Lock()
	w.touchConnLocked(conn, replied, time.Now())
	w.Unlock()
}

func drainTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	if d < 0 {
		d = 0
	}
	drainTimer(t)
	t.Reset(d)
}

func (w *udpWorker) closeExpiredConns() {
	for {
		var conn *udpConn
		w.Lock()
		if len(w.timeoutHeap) > 0 {
			now := time.Now()
			if !w.timeoutHeap[0].deadline.After(now) {
				conn = heap.Pop(&w.timeoutHeap).(*udpConn)
				if current, found := w.activeConn[conn.id]; found && current == conn {
					delete(w.activeConn, conn.id)
				}
			}
		}
		w.Unlock()
		if conn == nil {
			return
		}
		if !conn.done.Done() {
			conn.Close()
		}
	}
}

func (w *udpWorker) timeoutLoop() {
	defer w.timeoutWG.Done()

	timer := time.NewTimer(time.Hour)
	drainTimer(timer)
	defer drainTimer(timer)

	for {
		w.Lock()
		stopCh := w.timeoutStop
		wakeCh := w.timeoutWake
		if stopCh == nil || wakeCh == nil {
			w.Unlock()
			return
		}
		if len(w.timeoutHeap) == 0 {
			w.Unlock()
			select {
			case <-wakeCh:
				continue
			case <-stopCh:
				return
			}
		}
		wait := time.Until(w.timeoutHeap[0].deadline)
		w.Unlock()

		resetTimer(timer, wait)
		select {
		case <-timer.C:
			w.closeExpiredConns()
		case <-wakeCh:
		case <-stopCh:
			return
		}
	}
}

func (w *udpWorker) startTimeoutManager() {
	w.Lock()
	if w.timeoutStop != nil {
		w.Unlock()
		return
	}
	w.timeoutWake = make(chan struct{}, 1)
	w.timeoutStop = make(chan struct{})
	w.timeoutHeap = make(udpConnTimeoutHeap, 0, 256)
	w.timeoutWG.Add(1)
	w.Unlock()

	go w.timeoutLoop()
}

func (w *udpWorker) getConnection(id connID) (*udpConn, bool) {
	w.Lock()
	defer w.Unlock()

	if conn, found := w.activeConn[id]; found && !conn.done.Done() {
		w.touchConnLocked(conn, false, time.Now())
		return conn, true
	}

	pReader, pWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(16*1024))
	baseCtx := w.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	procCtx, cancel := context.WithCancel(baseCtx)
	conn := &udpConn{
		id:     id,
		ctx:    procCtx,
		reader: pReader,
		writer: pWriter,
		output: func(b []byte) (int, error) {
			return w.hub.WriteTo(b, id.src)
		},
		remote: &net.UDPAddr{
			IP:   id.src.Address.IP(),
			Port: int(id.src.Port),
		},
		local: &net.UDPAddr{
			IP:   w.address.IP(),
			Port: int(w.port),
		},
		done:      done.New(),
		uplink:    w.uplinkCounter,
		downlink:  w.downlinkCounter,
		cancel:    cancel,
		heapIndex: -1,
	}
	conn.onActivity = func(replied bool) {
		w.touchConn(conn, replied)
	}
	w.activeConn[id] = conn
	w.addConnTimeoutLocked(conn, time.Now())
	return conn, false
}

func (w *udpWorker) callback(b *buf.Buffer, source net.Destination, originalDest net.Destination) {
	id := connID{
		src: source,
	}
	if originalDest.IsValid() {
		if !w.cone {
			id.dest = originalDest
		}
		b.UDP = &originalDest
	}
	conn, existing := w.getConnection(id)

	// payload will be discarded in pipe is full.
	conn.writer.WriteMultiBuffer(buf.MultiBuffer{b})

	if !existing {
		go func() {
			ctx := conn.ctx
			sid := session.NewID()
			ctx = c.ContextWithID(ctx, sid)

			outbounds := []*session.Outbound{{}}
			if originalDest.IsValid() {
				outbounds[0].Target = originalDest
			}
			ctx = session.ContextWithOutbounds(ctx, outbounds)
			local := net.DestinationFromAddr(w.hub.Addr())
			if local.Address == net.AnyIP || local.Address == net.AnyIPv6 {
				if source.Address.Family().IsIPv4() {
					local.Address = net.AnyIP
				} else if source.Address.Family().IsIPv6() {
					local.Address = net.AnyIPv6
				}
			}

			ctx = session.ContextWithInbound(ctx, &session.Inbound{
				Source:      source,
				Local:       local, // Due to some limitations, in UDP connections, localIP is always equal to listen interface IP
				Gateway:     net.UDPDestination(w.address, w.port),
				Transparent: isTransparentInbound(w.stream),
				Tag:         w.tag,
				Conn:        conn,
			})
			content := new(session.Content)
			if w.sniffingConfig != nil {
				content.SniffingRequest.Enabled = w.sniffingConfig.Enabled
				content.SniffingRequest.OverrideDestinationForProtocol = w.sniffingConfig.DestinationOverride
				content.SniffingRequest.ExcludeForDomain = w.sniffingConfig.DomainsExcluded
				content.SniffingRequest.MetadataOnly = w.sniffingConfig.MetadataOnly
				content.SniffingRequest.RouteOnly = w.sniffingConfig.RouteOnly
			}
			ctx = session.ContextWithContent(ctx, content)
			if err := w.proxy.Process(ctx, net.Network_UDP, conn, w.dispatcher); err != nil {
				errors.LogInfoInner(ctx, err, "connection ends")
			}
			conn.Close()
			w.removeConnIfMatch(id, conn)
		}()
	}
}

func (w *udpWorker) removeConnIfMatch(id connID, conn *udpConn) {
	w.Lock()
	if current, found := w.activeConn[id]; found && current == conn {
		delete(w.activeConn, id)
		w.removeConnTimeoutLocked(conn)
	}
	w.Unlock()
}

func (w *udpWorker) handlePackets() {
	receive := w.hub.Receive()
	for payload := range receive {
		w.callback(payload.Payload, payload.Source, payload.Target)
	}
}

func coneFromContext(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	if v, ok := ctx.Value("cone").(bool); ok {
		return v
	}
	return true
}

func (w *udpWorker) Start() error {
	w.activeConn = make(map[connID]*udpConn, 16)
	w.startTimeoutManager()

	ctx := context.Background()
	h, err := udp.ListenUDP(ctx, w.address, w.port, w.stream, udp.HubCapacity(256))
	if err != nil {
		w.Lock()
		stopCh := w.timeoutStop
		w.timeoutStop = nil
		w.timeoutWake = nil
		w.Unlock()
		if stopCh != nil {
			close(stopCh)
			w.timeoutWG.Wait()
		}
		return err
	}

	w.cone = coneFromContext(w.ctx)

	w.hub = h
	go w.handlePackets()
	return nil
}

func (w *udpWorker) Close() error {
	var errs []interface{}
	var conns []*udpConn
	var hub *udp.Hub
	var stopCh chan struct{}

	w.Lock()
	for id, conn := range w.activeConn {
		delete(w.activeConn, id)
		w.removeConnTimeoutLocked(conn)
		conns = append(conns, conn)
	}
	stopCh = w.timeoutStop
	w.timeoutStop = nil
	w.timeoutWake = nil
	hub = w.hub
	w.hub = nil
	w.Unlock()

	if stopCh != nil {
		close(stopCh)
		w.timeoutWG.Wait()
	}

	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if hub != nil {
		if err := hub.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := common.Close(w.proxy); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.New("failed to close all resources").Base(errors.New(serial.Concat(errs...)))
	}
	return nil
}

func (w *udpWorker) Port() net.Port {
	return w.port
}

func (w *udpWorker) Proxy() proxy.Inbound {
	return w.proxy
}

type dsWorker struct {
	address         net.Address
	proxy           proxy.Inbound
	stream          *internet.MemoryStreamConfig
	tag             string
	dispatcher      routing.Dispatcher
	sniffingConfig  *proxyman.SniffingConfig
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter

	hub internet.Listener

	ctx context.Context
}

func (w *dsWorker) callback(conn stat.Connection) {
	ctx, cancel := context.WithCancel(w.ctx)
	sid := session.NewID()
	ctx = c.ContextWithID(ctx, sid)

	if w.uplinkCounter != nil || w.downlinkCounter != nil {
		conn = &stat.CounterConnection{
			Connection:   conn,
			ReadCounter:  w.uplinkCounter,
			WriteCounter: w.downlinkCounter,
		}
	}
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source:      net.DestinationFromAddr(conn.RemoteAddr()),
		Local:       net.DestinationFromAddr(conn.LocalAddr()),
		Gateway:     net.UnixDestination(w.address),
		Transparent: false,
		Tag:         w.tag,
		Conn:        conn,
	})

	content := new(session.Content)
	if w.sniffingConfig != nil {
		content.SniffingRequest.Enabled = w.sniffingConfig.Enabled
		content.SniffingRequest.OverrideDestinationForProtocol = w.sniffingConfig.DestinationOverride
		content.SniffingRequest.ExcludeForDomain = w.sniffingConfig.DomainsExcluded
		content.SniffingRequest.MetadataOnly = w.sniffingConfig.MetadataOnly
		content.SniffingRequest.RouteOnly = w.sniffingConfig.RouteOnly
	}
	ctx = session.ContextWithContent(ctx, content)

	if err := w.proxy.Process(ctx, net.Network_UNIX, conn, w.dispatcher); err != nil {
		errors.LogInfoInner(ctx, err, "connection ends")
	}
	cancel()
	if err := conn.Close(); err != nil {
		errors.LogInfoInner(ctx, err, "failed to close connection")
	}
}

func (w *dsWorker) Proxy() proxy.Inbound {
	return w.proxy
}

func (w *dsWorker) Port() net.Port {
	return net.Port(0)
}

func (w *dsWorker) Start() error {
	ctx := context.Background()
	hub, err := internet.ListenUnix(ctx, w.address, w.stream, func(conn stat.Connection) {
		go w.callback(conn)
	})
	if err != nil {
		return errors.New("failed to listen Unix Domain Socket on ", w.address).AtWarning().Base(err)
	}
	w.hub = hub
	return nil
}

func (w *dsWorker) Close() error {
	var errs []interface{}
	if w.hub != nil {
		if err := common.Close(w.hub); err != nil {
			errs = append(errs, err)
		}
		if err := common.Close(w.proxy); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.New("failed to close all resources").Base(errors.New(serial.Concat(errs...)))
	}

	return nil
}

func IsLocal(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
