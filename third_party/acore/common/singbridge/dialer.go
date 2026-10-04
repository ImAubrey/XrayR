package singbridge

import (
	"context"
	"os"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/net/cnc"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/proxy"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/internet"
	"github.com/ImAubrey/acore/transport/pipe"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ N.Dialer = (*AcoreDialer)(nil)

type AcoreDialer struct {
	internet.Dialer
}

func NewDialer(dialer internet.Dialer) *AcoreDialer {
	return &AcoreDialer{dialer}
}

func (d *AcoreDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.Dialer.Dial(ctx, ToDestination(destination, ToNetwork(network)))
}

func (d *AcoreDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type AcoreOutboundDialer struct {
	outbound proxy.Outbound
	dialer   internet.Dialer
}

func NewOutboundDialer(outbound proxy.Outbound, dialer internet.Dialer) *AcoreOutboundDialer {
	return &AcoreOutboundDialer{outbound, dialer}
}

func (d *AcoreOutboundDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.Target = ToDestination(destination, ToNetwork(network))

	opts := []pipe.Option{pipe.WithSizeLimit(64 * 1024)}
	uplinkReader, uplinkWriter := pipe.New(opts...)
	downlinkReader, downlinkWriter := pipe.New(opts...)
	conn := cnc.NewConnection(cnc.ConnectionInputMulti(downlinkWriter), cnc.ConnectionOutputMulti(uplinkReader))
	go d.outbound.Process(ctx, &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}, d.dialer)
	return conn, nil
}

func (d *AcoreOutboundDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
