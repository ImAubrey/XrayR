package dispatcher

import (
	"context"
	"sync"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/log"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
	feature_firewall "github.com/ImAubrey/acore/features/firewall"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
	routing_session "github.com/ImAubrey/acore/features/routing/session"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination net.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	ctx, conn := d.trackConnection(ctx, destination)

	sniffingRequest := content.SniffingRequest
	inbound, outbound := d.getLink(ctx)
	if conn != nil {
		if setter, ok := conn.(interface{ SetCloser(func()) }); ok {
			sessionInbound := session.InboundFromContext(ctx)
			var inboundConn net.Conn
			if sessionInbound != nil {
				inboundConn = sessionInbound.Conn
			}
			var outboundConn net.Conn
			if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
				outboundConn = outbounds[len(outbounds)-1].Conn
			}
			inboundLink := inbound
			outboundLink := outbound
			setter.SetCloser(func() {
				if inboundConn != nil {
					common.Close(inboundConn)
				}
				if outboundConn != nil {
					common.Close(outboundConn)
				}
				common.Interrupt(inboundLink.Reader)
				common.Interrupt(inboundLink.Writer)
				common.Interrupt(outboundLink.Reader)
				common.Interrupt(outboundLink.Writer)
			})
		}
	}
	if conn != nil {
		inbound.Reader = conntrack.NewCountingReader(inbound.Reader, conn.AddDownload)
		inbound.Writer = conntrack.NewCountingWriter(inbound.Writer, conn.AddUpload)
	}
	routingCtx := routing_session.AsRoutingContext(ctx)
	forceSniffing := d.buildForceSniffingConfig(ctx, routingCtx)
	if !sniffingRequest.Enabled && !forceSniffing.enabled() {
		d.applyDomainRecover(ob, destination, nil, nil, conn)
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func() {
			originalDestination := destination
			result, err := d.sniffAndApplyRouting(
				ctx,
				routingCtx,
				content,
				sniffingRequest,
				forceSniffing,
				outbound,
				outbound.Reader.(*pipe.Reader),
				&destination,
				ob,
				conn,
			)
			d.applyDomainRecover(ob, originalDestination, result, err, conn)
			d.routedDispatch(ctx, outbound, destination)
		}()
	}
	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return errors.New("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	ctx, conn := d.trackConnection(ctx, destination)
	outbound = d.WrapLink(ctx, outbound)
	if conn != nil {
		if setter, ok := conn.(interface{ SetCloser(func()) }); ok {
			sessionInbound := session.InboundFromContext(ctx)
			var inboundConn net.Conn
			if sessionInbound != nil {
				inboundConn = sessionInbound.Conn
			}
			var outboundConn net.Conn
			if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
				outboundConn = outbounds[len(outbounds)-1].Conn
			}
			link := outbound
			setter.SetCloser(func() {
				if inboundConn != nil {
					common.Close(inboundConn)
				}
				if outboundConn != nil {
					common.Close(outboundConn)
				}
				common.Interrupt(link.Reader)
				common.Interrupt(link.Writer)
			})
		}
	}
	sniffingRequest := content.SniffingRequest
	routingCtx := routing_session.AsRoutingContext(ctx)
	forceSniffing := d.buildForceSniffingConfig(ctx, routingCtx)
	if !sniffingRequest.Enabled && !forceSniffing.enabled() {
		d.applyDomainRecover(ob, destination, nil, nil, conn)
		d.routedDispatch(ctx, outbound, destination)
	} else {
		originalDestination := destination
		result, err := d.sniffAndApplyRouting(
			ctx,
			routingCtx,
			content,
			sniffingRequest,
			forceSniffing,
			outbound,
			outbound.Reader.(buf.TimeoutReader),
			&destination,
			ob,
			conn,
		)
		d.applyDomainRecover(ob, originalDestination, result, err, conn)
		d.routedDispatch(ctx, outbound, destination)
	}

	return nil
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination net.Destination) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	content := session.ContentFromContext(ctx)
	conn := conntrack.ConnectionFromContext(ctx)
	if conn != nil {
		defer conn.Close()
	}

	var handler outbound.Handler
	var pickedRoute routing.Route

	routingLink := routing_session.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0
	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			isPickRoute = 1
			errors.LogInfo(ctx, "taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]")
			handler = h
		} else {
			errors.LogError(ctx, "non existing tag for platform initialized detour: ", forcedOutboundTag)
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return
		}
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			pickedRoute = route
			outTag := route.GetOutboundTag()
			if h := d.ohm.GetHandler(outTag); h != nil {
				isPickRoute = 2
				if route.GetRuleTag() == "" {
					errors.LogInfo(ctx, "taking detour [", outTag, "] for [", destination, "]")
				} else {
					errors.LogInfo(ctx, "Hit route rule: [", route.GetRuleTag(), "] so taking detour [", outTag, "] for [", destination, "]")
				}
				handler = h
			} else {
				errors.LogWarning(ctx, "non existing outTag: ", outTag)
				common.Close(link.Writer)
				common.Interrupt(link.Reader)
				return // DO NOT CHANGE: the traffic shouldn't be processed by default outbound if the specified outbound tag doesn't exist (yet), e.g., VLESS Reverse Proxy
			}
		} else {
			errors.LogInfo(ctx, "default route for ", destination)
		}
	}

	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if pickedRoute != nil {
		applyRouteReLookup(ob, pickedRoute)
		applyRouteDestVlessRoute(ob, pickedRoute)
		if conn != nil {
			conn.SetRouteTag(pickedRoute.GetRuleTag())
			if content != nil {
				if ja4 := content.Attribute("ja4"); ja4 != "" {
					conn.SetJA4(ja4)
				}
				if ja4Tag := content.Attribute("ja4_tag"); ja4Tag != "" {
					conn.SetJA4Tag(ja4Tag)
				}
			}
		}
	}

	if handler == nil {
		errors.LogInfo(ctx, "default outbound handler not exist")
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
		return
	}

	ob.Tag = handler.Tag()
	if conn != nil {
		conn.SetOutboundTag(ob.Tag)
	}
	firewallCtx := routing.Context(routingLink)
	if pickedRoute != nil {
		firewallCtx = pickedRoute
	}
	firewallDestination := ob.Target.String()
	if firewallDestination == "" {
		firewallDestination = destination.String()
	}
	if d.enforceFirewall(ctx, firewallCtx, firewallDestination, link) {
		return
	}
	if d.fw != nil {
		var blockOnce sync.Once
		if observer := d.fw.NewFlowObserver(ctx, firewallCtx, func(decision feature_firewall.Decision) {
			blockOnce.Do(func() {
				d.applyFirewallDecision(ctx, decision, firewallDestination, link)
			})
		}); observer != nil {
			ctx = feature_firewall.ContextWithFlowObserver(ctx, observer)
		}
	}
	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			if inTag == "" {
				accessMessage.Detour = tag
			} else if isPickRoute == 1 {
				accessMessage.Detour = inTag + " ==> " + tag
			} else if isPickRoute == 2 {
				accessMessage.Detour = inTag + " -> " + tag
			} else {
				accessMessage.Detour = inTag + " >> " + tag
			}
		}
		log.Record(accessMessage)
	}

	handler.Dispatch(ctx, link)
}

func applyRouteReLookup(ob *session.Outbound, pickedRoute routing.Route) {
	rl, ok := pickedRoute.(interface {
		ReLookup() bool
	})
	if !ok {
		return
	}
	if !rl.ReLookup() {
		return
	}
	if !ob.RouteTarget.IsValid() || !ob.RouteTarget.Address.Family().IsDomain() {
		return
	}
	ob.ReLookup = true
	ob.Target = ob.RouteTarget
	ob.TargetIPs = nil
}

func applyRouteDestVlessRoute(ob *session.Outbound, pickedRoute routing.Route) {
	dr, ok := pickedRoute.(interface {
		DestVlessRoute() (net.Port, bool)
	})
	if !ok {
		return
	}
	port, ok := dr.DestVlessRoute()
	if !ok {
		return
	}
	ob.DestVlessRoute = port
	ob.HasDestVlessRoute = true
}
