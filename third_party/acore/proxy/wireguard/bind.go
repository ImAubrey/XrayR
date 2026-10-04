package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/transport/internet"
)

type netReadInfo struct {
	// status
	waiter sync.WaitGroup
	// param
	buff []byte
	// result
	bytes    int
	endpoint conn.Endpoint
	err      error
}

// reduce duplicated code
type netBind struct {
	dns       dns.Client
	dnsOption dns.IPOption

	workers   int
	readQueue chan *netReadInfo
}

// SetMark implements conn.Bind
func (bind *netBind) SetMark(mark uint32) error {
	return nil
}

// ParseEndpoint implements conn.Bind
func (n *netBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ipStr, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	addr := net.ParseAddress(ipStr)
	if addr.Family() == net.AddressFamilyDomain {
		ips, _, err := n.dns.LookupIP(addr.Domain(), n.dnsOption)
		if err != nil {
			return nil, err
		} else if len(ips) == 0 {
			return nil, dns.ErrEmptyResponse
		}
		addr = net.IPAddress(ips[0])
	}

	dst := net.Destination{
		Address: addr,
		Port:    net.Port(portNum),
		Network: net.Network_UDP,
	}

	return &netEndpoint{
		dst: dst,
	}, nil
}

// BatchSize implements conn.Bind
func (bind *netBind) BatchSize() int {
	return 1
}

// Open implements conn.Bind
func (bind *netBind) Open(uport uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.readQueue = make(chan *netReadInfo)

	fun := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		defer func() {
			if r := recover(); r != nil {
				n = 0
				err = errors.New("channel closed")
			}
		}()

		r := &netReadInfo{
			buff: bufs[0],
		}
		r.waiter.Add(1)
		bind.readQueue <- r
		r.waiter.Wait() // wait read goroutine done, or we will miss the result
		sizes[0], eps[0] = r.bytes, r.endpoint
		return 1, r.err
	}
	workers := bind.workers
	if workers <= 0 {
		workers = 1
	}
	arr := make([]conn.ReceiveFunc, workers)
	for i := 0; i < workers; i++ {
		arr[i] = fun
	}

	return arr, uint16(uport), nil
}

// Close implements conn.Bind
func (bind *netBind) Close() error {
	if bind.readQueue != nil {
		close(bind.readQueue)
	}
	return nil
}

type netBindClient struct {
	netBind

	mu       sync.RWMutex
	ctx      context.Context
	dialer   internet.Dialer
	reserved []byte

	endpointsMu sync.Mutex
	endpoints   []*netEndpoint
}

func (bind *netBindClient) ParseEndpoint(s string) (conn.Endpoint, error) {
	ep, err := bind.netBind.ParseEndpoint(s)
	if err != nil {
		return nil, err
	}
	if nep, ok := ep.(*netEndpoint); ok {
		bind.endpointsMu.Lock()
		bind.endpoints = append(bind.endpoints, nep)
		bind.endpointsMu.Unlock()
	}
	return ep, nil
}

func (bind *netBindClient) Update(ctx context.Context, dialer internet.Dialer, reserved []byte) {
	bind.mu.Lock()
	dialerChanged := bind.dialer != nil && bind.dialer != dialer
	bind.ctx = ctx
	bind.dialer = dialer
	bind.reserved = reserved
	bind.mu.Unlock()

	if dialerChanged {
		bind.endpointsMu.Lock()
		endpoints := append([]*netEndpoint(nil), bind.endpoints...)
		bind.endpointsMu.Unlock()
		for _, ep := range endpoints {
			ep.closeConn()
		}
	}
}

func (bind *netBindClient) connectTo(endpoint *netEndpoint) (net.Conn, error) {
	if existing := endpoint.getConn(); existing != nil {
		return existing, nil
	}

	bind.mu.RLock()
	ctx := bind.ctx
	dialer := bind.dialer
	bind.mu.RUnlock()
	if dialer == nil {
		return nil, errors.New("dialer is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c, err := dialer.Dial(ctx, endpoint.dst)
	if err != nil {
		return nil, err
	}
	if !endpoint.setConnIfNil(c) {
		_ = c.Close()
		if existing := endpoint.getConn(); existing != nil {
			return existing, nil
		}
		return nil, errors.New("endpoint connection was closed")
	}

	go func(readQueue <-chan *netReadInfo, endpoint *netEndpoint, c net.Conn) {
		for {
			v, ok := <-readQueue
			if !ok {
				return
			}
			i, err := c.Read(v.buff)

			if i > 3 {
				v.buff[1] = 0
				v.buff[2] = 0
				v.buff[3] = 0
			}

			v.bytes = i
			v.endpoint = endpoint
			v.err = err
			v.waiter.Done()
			if err != nil {
				endpoint.clearConnIfMatch(c)
				return
			}
		}
	}(bind.readQueue, endpoint, c)

	return c, nil
}

func (bind *netBindClient) Send(buff [][]byte, endpoint conn.Endpoint) error {
	var err error

	nend, ok := endpoint.(*netEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	c, err := bind.connectTo(nend)
	if err != nil {
		return err
	}

	bind.mu.RLock()
	reserved := bind.reserved
	bind.mu.RUnlock()

	for _, buff := range buff {
		if len(buff) > 3 && len(reserved) == 3 {
			copy(buff[1:], reserved)
		}
		if _, err = c.Write(buff); err != nil {
			return err
		}
	}
	return nil
}

type netBindServer struct {
	netBind
}

func (bind *netBindServer) Send(buff [][]byte, endpoint conn.Endpoint) error {
	var err error

	nend, ok := endpoint.(*netEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	c := nend.getConn()
	if c == nil {
		return errors.New("connection not open yet")
	}

	for _, buff := range buff {
		if _, err = c.Write(buff); err != nil {
			return err
		}
	}

	return err
}

type netEndpoint struct {
	dst  net.Destination
	mu   sync.Mutex
	conn net.Conn
}

func (*netEndpoint) ClearSrc() {}

func (e *netEndpoint) DstIP() netip.Addr {
	return netip.Addr{}
}

func (e *netEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (e *netEndpoint) DstToBytes() []byte {
	var dat []byte
	if e.dst.Address.Family().IsIPv4() {
		dat = e.dst.Address.IP().To4()[:]
	} else {
		dat = e.dst.Address.IP().To16()[:]
	}
	dat = append(dat, byte(e.dst.Port), byte(e.dst.Port>>8))
	return dat
}

func (e *netEndpoint) DstToString() string {
	return e.dst.NetAddr()
}

func (e *netEndpoint) SrcToString() string {
	return ""
}

func (e *netEndpoint) getConn() net.Conn {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	c := e.conn
	e.mu.Unlock()
	return c
}

func (e *netEndpoint) setConnIfNil(c net.Conn) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		return false
	}
	e.conn = c
	return true
}

func (e *netEndpoint) setConn(c net.Conn) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.conn = c
	e.mu.Unlock()
}

func (e *netEndpoint) clearConn() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.conn = nil
	e.mu.Unlock()
}

func (e *netEndpoint) clearConnIfMatch(c net.Conn) {
	if e == nil {
		return
	}
	e.mu.Lock()
	if e.conn == c {
		e.conn = nil
	}
	e.mu.Unlock()
	_ = c.Close()
}

func (e *netEndpoint) closeConn() {
	if e == nil {
		return
	}
	e.mu.Lock()
	c := e.conn
	e.conn = nil
	e.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func toNetIpAddr(addr net.Address) netip.Addr {
	if addr.Family().IsIPv4() {
		ip := addr.IP()
		return netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
	} else {
		ip := addr.IP()
		arr := [16]byte{}
		for i := 0; i < 16; i++ {
			arr[i] = ip[i]
		}
		return netip.AddrFrom16(arr)
	}
}
