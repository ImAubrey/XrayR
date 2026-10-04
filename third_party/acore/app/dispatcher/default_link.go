package dispatcher

import (
	"context"
	"time"

	"github.com/ImAubrey/acore/common/buf"
	xctx "github.com/ImAubrey/acore/common/ctx"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/policy"
	"github.com/ImAubrey/acore/features/stats"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

func (d *DefaultDispatcher) getLink(ctx context.Context) (*transport.Link, *transport.Link) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	if user != nil && len(user.Email) > 0 {
		p := d.policy.ForLevel(user.Level)
		if p.Stats.UserUplink {
			name := "user>>>" + user.Email + ">>>traffic>>>uplink"
			if c, _ := stats.GetOrRegisterCounter(d.stats, name); c != nil {
				inboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  inboundLink.Writer,
				}
			}
		}
		if p.Stats.UserDownlink {
			name := "user>>>" + user.Email + ">>>traffic>>>downlink"
			if c, _ := stats.GetOrRegisterCounter(d.stats, name); c != nil {
				outboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  outboundLink.Writer,
				}
			}
		}

		if p.Stats.UserOnline {
			name := "user>>>" + user.Email + ">>>online"
			if om, _ := stats.GetOrRegisterOnlineMap(d.stats, name); om != nil {
				sessionInbounds := session.InboundFromContext(ctx)
				userIP := sessionInbounds.Source.Address.String()
				om.AddIP(userIP)
				// log Online user with ips
				// errors.LogDebug(ctx, "user>>>" + user.Email + ">>>online", om.Count(), om.List())

			}
		}
	}

	return inboundLink, outboundLink
}

func (d *DefaultDispatcher) trackConnection(ctx context.Context, destination net.Destination) (context.Context, conntrack.Connection) {
	if d.ct == nil {
		return ctx, nil
	}

	inbound := session.InboundFromContext(ctx)
	content := session.ContentFromContext(ctx)
	var outbound *session.Outbound
	if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
		outbound = outbounds[len(outbounds)-1]
	}

	meta := conntrack.Meta{
		ID:          uint32(xctx.IDFromContext(ctx)),
		Start:       time.Now(),
		Network:     destination.Network,
		Destination: destination,
		Target:      destination,
	}

	if inbound != nil {
		meta.Source = inbound.Source
		meta.Local = inbound.Local
		meta.InboundTag = inbound.Tag
		meta.InboundName = inbound.Name
		if inbound.User != nil {
			meta.User = inbound.User.Email
		}
	}
	if outbound != nil {
		if outbound.OriginalTarget.IsValid() {
			meta.Destination = outbound.OriginalTarget
		}
		if outbound.Target.IsValid() {
			meta.Target = outbound.Target
		}
		meta.OutboundTag = outbound.Tag
		meta.OutboundName = outbound.Name
	}
	if content != nil {
		if content.Protocol != "" {
			meta.Protocol = content.Protocol
		}
		if alpn := content.Attribute("alpn"); alpn != "" {
			meta.ALPN = alpn
		}
		if ja4 := content.Attribute("ja4"); ja4 != "" {
			meta.JA4 = ja4
		}
		if ja4Tag := content.Attribute("ja4_tag"); ja4Tag != "" {
			meta.JA4Tag = ja4Tag
		}
	}

	conn := d.ct.NewConnection(meta)
	if conn == nil {
		return ctx, nil
	}
	return conntrack.ContextWithConnection(ctx, conn), conn
}

func WrapLink(ctx context.Context, policyManager policy.Manager, statsManager stats.Manager, link *transport.Link) *transport.Link {
	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	link.Reader = &buf.TimeoutWrapperReader{Reader: link.Reader}

	if user != nil && len(user.Email) > 0 {
		p := policyManager.ForLevel(user.Level)
		if p.Stats.UserUplink {
			name := "user>>>" + user.Email + ">>>traffic>>>uplink"
			if c, _ := stats.GetOrRegisterCounter(statsManager, name); c != nil {
				link.Reader.(*buf.TimeoutWrapperReader).Counter = c
			}
		}
		if p.Stats.UserDownlink {
			name := "user>>>" + user.Email + ">>>traffic>>>downlink"
			if c, _ := stats.GetOrRegisterCounter(statsManager, name); c != nil {
				link.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  link.Writer,
				}
			}
		}
		if p.Stats.UserOnline {
			name := "user>>>" + user.Email + ">>>online"
			if om, _ := stats.GetOrRegisterOnlineMap(statsManager, name); om != nil {
				sessionInbounds := session.InboundFromContext(ctx)
				userIP := sessionInbounds.Source.Address.String()
				om.AddIP(userIP)
				// log Online user with ips
				// errors.LogDebug(ctx, "user>>>" + user.Email + ">>>online", om.Count(), om.List())
			}
		}
	}

	if conn := conntrack.ConnectionFromContext(ctx); conn != nil {
		// WrapLink is used for outbound links (DispatchLink), where Reader is uplink and Writer is downlink.
		link.Reader = conntrack.NewCountingReader(link.Reader, conn.AddUpload)
		link.Writer = conntrack.NewCountingWriter(link.Writer, conn.AddDownload)
	}

	return link
}

// WrapLink implements routing.WrapLinkDispatcher.
func (d *DefaultDispatcher) WrapLink(ctx context.Context, link *transport.Link) *transport.Link {
	return WrapLink(ctx, d.policy, d.stats, link)
}
