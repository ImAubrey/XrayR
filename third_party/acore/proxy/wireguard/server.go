package wireguard

import (
	"context"
	goerrors "errors"
	"io"
	gonet "net"
	"net/netip"
	"strings"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	c "github.com/ImAubrey/acore/common/ctx"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/log"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/common/signal"
	"github.com/ImAubrey/acore/common/task"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/policy"
	"github.com/ImAubrey/acore/features/routing"
	"github.com/ImAubrey/acore/transport/internet/stat"
)

var nullDestination = net.TCPDestination(net.AnyIP, 0)

type peerUser struct {
	label   string
	allowed []netip.Prefix
}

type Server struct {
	bindServer *netBindServer
	tun        Tunnel
	peerUsers  []peerUser

	info          routingInfo
	policyManager policy.Manager
}

type routingInfo struct {
	ctx        context.Context
	dispatcher routing.Dispatcher
	inboundTag *session.Inbound
	contentTag *session.Content
}

func NewServer(ctx context.Context, conf *DeviceConfig) (*Server, error) {
	v := core.MustFromContext(ctx)

	endpoints, hasIPv4, hasIPv6, err := parseEndpoints(conf)
	if err != nil {
		return nil, err
	}

	server := &Server{
		bindServer: &netBindServer{
			netBind: netBind{
				dns: v.GetFeature(dns.ClientType()).(dns.Client),
				dnsOption: dns.IPOption{
					IPv4Enable: hasIPv4,
					IPv6Enable: hasIPv6,
				},
			},
		},
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		peerUsers:     buildPeerUsers(conf.Peers),
	}

	tun, err := conf.createTun()(endpoints, int(conf.Mtu), server.forwardConnection)
	if err != nil {
		return nil, err
	}

	if err = tun.BuildDevice(createIPCRequest(conf), server.bindServer); err != nil {
		_ = tun.Close()
		return nil, err
	}

	server.tun = tun
	return server, nil
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	if s.tun != nil {
		_ = s.tun.Close()
		s.tun = nil
	}
	if s.bindServer != nil {
		_ = s.bindServer.Close()
	}
	return nil
}

// Network implements proxy.Inbound.
func (*Server) Network() []net.Network {
	return []net.Network{net.Network_UDP}
}

// Process implements proxy.Inbound.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	s.info = routingInfo{
		ctx:        ctx,
		dispatcher: dispatcher,
		inboundTag: session.InboundFromContext(ctx),
		contentTag: session.ContentFromContext(ctx),
	}

	ep, err := s.bindServer.ParseEndpoint(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	nep := ep.(*netEndpoint)
	nep.setConn(conn)

	reader := buf.NewPacketReader(conn)
	for {
		mpayload, err := reader.ReadMultiBuffer()
		if err != nil {
			return err
		}

		for _, payload := range mpayload {
			v, ok := <-s.bindServer.readQueue
			if !ok {
				return nil
			}
			i, err := payload.Read(v.buff)

			v.bytes = i
			v.endpoint = nep
			v.err = err
			v.waiter.Done()
			if err != nil && goerrors.Is(err, io.EOF) {
				nep.clearConn()
				return nil
			}
		}
	}
}

func (s *Server) resolveUserEmail(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	ra := conn.RemoteAddr()
	if ra == nil {
		return ""
	}
	host, _, err := gonet.SplitHostPort(ra.String())
	if err != nil {
		host = strings.TrimSpace(ra.String())
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}

	bestBits := -1
	bestLabel := ""
	ambiguous := false
	for _, peer := range s.peerUsers {
		for _, prefix := range peer.allowed {
			if prefix.Contains(ip) {
				bits := prefix.Bits()
				if bits > bestBits {
					bestBits = bits
					bestLabel = peer.label
					ambiguous = false
					continue
				}
				if bits == bestBits && bestLabel != peer.label {
					ambiguous = true
				}
			}
		}
	}
	if bestBits >= 0 && bestLabel != "" && !ambiguous {
		return bestLabel
	}
	return host
}

func (s *Server) forwardConnection(dest net.Destination, conn net.Conn) {
	if s.info.dispatcher == nil {
		errors.LogError(s.info.ctx, "unexpected: dispatcher == nil")
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(core.ToBackgroundDetachedContext(s.info.ctx))
	sid := session.NewID()
	ctx = c.ContextWithID(ctx, sid)
	inbound := session.Inbound{} // since promiscuousModeHandler mixed-up context, we shallow copy inbound (tag) and content (configs)
	if s.info.inboundTag != nil {
		inbound = *s.info.inboundTag
	}
	inbound.Name = "wireguard"
	inbound.CanSpliceCopy = 3

	// overwrite the source to use the tun address for each sub context.
	// Since gvisor.ForwarderRequest doesn't provide any info to associate the sub-context with the Parent context
	// Currently we have no way to link to the original source address
	inbound.Source = net.DestinationFromAddr(conn.RemoteAddr())
	ctx = session.ContextWithInbound(ctx, &inbound)
	if s.info.contentTag != nil {
		ctx = session.ContextWithContent(ctx, s.info.contentTag)
	}
	ctx = session.SubContextFromMuxInbound(ctx)

	if email := s.resolveUserEmail(conn); email != "" {
		inbound.User = &protocol.MemoryUser{
			Email: email,
			Level: 0,
		}
	}

	plcy := s.policyManager.ForLevel(0)
	timer := signal.CancelAfterInactivity(ctx, cancel, plcy.Timeouts.ConnectionIdle)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   nullDestination,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})

	link, err := s.info.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		errors.LogErrorInner(ctx, err, "dispatch connection")
	}
	defer cancel()

	requestDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)
		if err := buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport all TCP request").Base(err)
		}

		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
		if err := buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer)); err != nil {
			return errors.New("failed to transport all TCP response").Base(err)
		}

		return nil
	}

	requestDonePost := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDonePost, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		errors.LogDebugInner(ctx, err, "connection ends")
		return
	}
}

func buildPeerUsers(peers []*PeerConfig) []peerUser {
	if len(peers) == 0 {
		return nil
	}
	out := make([]peerUser, 0, len(peers))
	for _, peer := range peers {
		if peer == nil {
			continue
		}

		label := strings.TrimSpace(peer.PublicKey)
		if label != "" {
			label = "wg:" + label
		}
		if label == "" {
			continue
		}

		prefixes := make([]netip.Prefix, 0, len(peer.AllowedIps))
		for _, raw := range peer.AllowedIps {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			// /0 is not usable for peer identity (it matches everyone).
			if prefix.Bits() == 0 {
				continue
			}
			prefixes = append(prefixes, prefix)
		}
		if len(prefixes) == 0 {
			continue
		}

		out = append(out, peerUser{
			label:   label,
			allowed: prefixes,
		})
	}
	return out
}
