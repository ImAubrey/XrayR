package outbound

import (
	"context"
	"net"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	v2net "github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/net/cnc"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

type connErrorTracker struct {
	ch chan error
}

func (t *connErrorTracker) SubmitError(err error) {
	if err == nil {
		return
	}
	select {
	case t.ch <- err:
	default:
	}
}

// DialOutboundConn builds a net.Conn by dispatching through an outbound handler.
// It is primarily used by observatory probes to reuse outbound dispatch logic.
func DialOutboundConn(ctx context.Context, handler outbound.Handler, tag string, dest v2net.Destination) (net.Conn, *session.Outbound, <-chan error, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if handler == nil {
		if tag == "" {
			tag = "unknown"
		}
		return nil, nil, nil, errors.New("outbound handler not found: " + tag)
	}
	if tag == "" {
		tag = handler.Tag()
	}
	ob := &session.Outbound{
		Target:         dest,
		OriginalTarget: dest,
		Tag:            tag,
	}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
	if session.ContentFromContext(ctx) == nil {
		ctx = session.ContextWithContent(ctx, &session.Content{})
	}
	tracker := &connErrorTracker{ch: make(chan error, 1)}
	ctx = session.TrackedConnectionError(ctx, tracker)

	ur, uw := pipe.New(pipe.OptionsFromContext(ctx)...)
	dr, dw := pipe.New(pipe.OptionsFromContext(ctx)...)
	go handler.Dispatch(ctx, &transport.Link{Reader: ur, Writer: dw})

	var readerOpt cnc.ConnectionOption
	if dest.Network == v2net.Network_TCP {
		readerOpt = cnc.ConnectionOutputMulti(dr)
	} else {
		readerOpt = cnc.ConnectionOutputMultiUDP(dr)
	}
	conn := cnc.NewConnection(
		cnc.ConnectionInputMulti(uw),
		readerOpt,
		cnc.ConnectionOnClose(common.ChainedClosable{uw, dw}),
	)
	return conn, ob, tracker.ch, nil
}
