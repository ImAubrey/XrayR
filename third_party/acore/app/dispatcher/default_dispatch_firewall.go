package dispatcher

import (
	"context"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/log"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/conntrack"
	feature_firewall "github.com/ImAubrey/acore/features/firewall"
	"github.com/ImAubrey/acore/features/routing"
	"github.com/ImAubrey/acore/transport"
)

func (d *DefaultDispatcher) enforceFirewall(ctx context.Context, routingCtx routing.Context, destination string, links ...*transport.Link) bool {
	if d == nil || d.fw == nil {
		return false
	}
	return d.applyFirewallDecision(ctx, d.fw.Evaluate(ctx, routingCtx), destination, links...)
}

func (d *DefaultDispatcher) applyFirewallDecision(ctx context.Context, decision feature_firewall.Decision, destination string, links ...*transport.Link) bool {
	if decision.Action != feature_firewall.ActionBlock {
		return false
	}

	if decision.RuleTag != "" {
		errors.LogInfo(ctx, "firewall blocked by rule [", decision.RuleTag, "] for [", destination, "]")
	} else {
		errors.LogInfo(ctx, "firewall blocked [", destination, "]")
	}
	if decision.Count > 0 && decision.Max > 0 {
		sourcePrefix := ""
		if decision.SourcePrefix != "" {
			sourcePrefix = " sourcePrefix=" + decision.SourcePrefix
		}
		destinationPrefix := ""
		if decision.DestinationPrefix != "" {
			destinationPrefix = " destinationPrefix=" + decision.DestinationPrefix
		}
		if decision.CounterMode == conntrack.CounterModeNewConnections && decision.Window > 0 {
			errors.LogInfo(ctx, "firewall counter exceeded: mode=newConnections window=", decision.Window, " current=", decision.Count, " max=", decision.Max, " source=", decision.SourceIP, " destination=", decision.DestinationIP, sourcePrefix, destinationPrefix)
		} else {
			errors.LogInfo(ctx, "firewall counter exceeded: mode=activeConnections current=", decision.Count, " max=", decision.Max, " source=", decision.SourceIP, " destination=", decision.DestinationIP, sourcePrefix, destinationPrefix)
		}
	}
	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		accessMessage.Status = log.AccessRejected
		if decision.RuleTag != "" {
			accessMessage.Reason = "firewall:" + decision.RuleTag
		} else {
			accessMessage.Reason = "firewall"
		}
		log.Record(accessMessage)
	}

	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
		common.Close(inbound.Conn)
	}
	if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
		if conn := outbounds[len(outbounds)-1].Conn; conn != nil {
			common.Close(conn)
		}
	}
	for _, link := range links {
		if link == nil {
			continue
		}
		common.Close(link.Writer)
		common.Interrupt(link.Reader)
	}
	if conn := conntrack.ConnectionFromContext(ctx); conn != nil {
		conn.Close()
	}
	return true
}
