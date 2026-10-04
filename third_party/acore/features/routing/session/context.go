package session

import (
	"context"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/features/routing"
)

// Context is an implementation of routing.Context, which is a wrapper of context.context with session info.
type Context struct {
	Inbound    *session.Inbound
	Outbound   *session.Outbound
	Content    *session.Content
	RuleTags   map[string]struct{}
	RuleMarked bool

	sourceIPsCached bool
	sourceIPs       []net.IP

	targetIPsCached bool
	targetIPs       []net.IP

	localIPsCached bool
	localIPs       []net.IP
}

// GetInboundTag implements routing.Context.
func (ctx *Context) GetInboundTag() string {
	if ctx.Inbound == nil {
		return ""
	}
	return ctx.Inbound.Tag
}

// GetSourceIPs implements routing.Context.
func (ctx *Context) GetSourceIPs() []net.IP {
	if ctx.sourceIPsCached {
		return ctx.sourceIPs
	}
	ctx.sourceIPsCached = true

	if ctx.Inbound == nil || !ctx.Inbound.Source.IsValid() {
		return nil
	}
	if ctx.Inbound.Source.Address.Family().IsIP() {
		ctx.sourceIPs = []net.IP{ctx.Inbound.Source.Address.IP()}
	}
	return ctx.sourceIPs
}

// GetSourcePort implements routing.Context.
func (ctx *Context) GetSourcePort() net.Port {
	if ctx.Inbound == nil || !ctx.Inbound.Source.IsValid() {
		return 0
	}
	return ctx.Inbound.Source.Port
}

// GetTargetIPs implements routing.Context.
func (ctx *Context) GetTargetIPs() []net.IP {
	if ctx.Outbound == nil || !ctx.Outbound.Target.IsValid() {
		return nil
	}

	if len(ctx.Outbound.TargetIPs) > 0 {
		return ctx.Outbound.TargetIPs
	}

	if ctx.targetIPsCached {
		return ctx.targetIPs
	}
	ctx.targetIPsCached = true

	if ctx.Outbound.Target.Address.Family().IsIP() {
		ctx.targetIPs = []net.IP{ctx.Outbound.Target.Address.IP()}
	}
	return ctx.targetIPs
}

// GetTargetPort implements routing.Context.
func (ctx *Context) GetTargetPort() net.Port {
	if ctx.Outbound == nil || !ctx.Outbound.Target.IsValid() {
		return 0
	}
	return ctx.Outbound.Target.Port
}

// GetLocalIPs implements routing.Context.
func (ctx *Context) GetLocalIPs() []net.IP {
	if ctx.localIPsCached {
		return ctx.localIPs
	}
	ctx.localIPsCached = true

	if ctx.Inbound == nil || !ctx.Inbound.Local.IsValid() {
		return nil
	}
	if ctx.Inbound.Local.Address.Family().IsIP() {
		ctx.localIPs = []net.IP{ctx.Inbound.Local.Address.IP()}
	}
	return ctx.localIPs
}

// GetLocalPort implements routing.Context.
func (ctx *Context) GetLocalPort() net.Port {
	if ctx.Inbound == nil || !ctx.Inbound.Local.IsValid() {
		return 0
	}
	return ctx.Inbound.Local.Port
}

// GetTargetDomain implements routing.Context.
func (ctx *Context) GetTargetDomain() string {
	if ctx.Outbound == nil || !ctx.Outbound.Target.IsValid() {
		return ""
	}
	dest := ctx.Outbound.RouteTarget
	if dest.IsValid() && dest.Address.Family().IsDomain() {
		return dest.Address.Domain()
	}

	dest = ctx.Outbound.Target
	if !dest.Address.Family().IsDomain() {
		return ""
	}
	return dest.Address.Domain()
}

// GetNetwork implements routing.Context.
func (ctx *Context) GetNetwork() net.Network {
	if ctx.Outbound == nil {
		return net.Network_Unknown
	}
	return ctx.Outbound.Target.Network
}

// GetProtocol implements routing.Context.
func (ctx *Context) GetProtocol() string {
	if ctx.Content == nil {
		return ""
	}
	return ctx.Content.Protocol
}

// GetUser implements routing.Context.
func (ctx *Context) GetUser() string {
	if ctx.Inbound == nil || ctx.Inbound.User == nil {
		return ""
	}
	return ctx.Inbound.User.Email
}

// GetVlessRoute implements routing.Context.
func (ctx *Context) GetVlessRoute() net.Port {
	if ctx.Inbound == nil {
		return 0
	}
	return ctx.Inbound.VlessRoute
}

// GetAttributes implements routing.Context.
func (ctx *Context) GetAttributes() map[string]string {
	if ctx.Content == nil {
		return nil
	}
	return ctx.Content.Attributes
}

// GetSkipDNSResolve implements routing.Context.
func (ctx *Context) GetSkipDNSResolve() bool {
	if ctx.Content == nil {
		return false
	}
	return ctx.Content.SkipDNSResolve
}

// AddRuleTag stores a matched rule tag into context.
func (ctx *Context) AddRuleTag(tag string) {
	if tag == "" {
		return
	}
	if ctx.RuleTags == nil {
		ctx.RuleTags = make(map[string]struct{})
	}
	ctx.RuleTags[tag] = struct{}{}
}

// HasRuleTag checks if a rule tag was matched before.
func (ctx *Context) HasRuleTag(tag string) bool {
	if ctx.RuleTags == nil {
		return false
	}
	_, ok := ctx.RuleTags[tag]
	return ok
}

// MarkRuleMatched sets a fast flag indicating a rule with "+" has matched.
func (ctx *Context) MarkRuleMatched() {
	ctx.RuleMarked = true
}

// HasRuleMark reports whether any "+" rule has matched before.
func (ctx *Context) HasRuleMark() bool {
	return ctx.RuleMarked
}

// AsRoutingContext creates a context from context.context with session info.
func AsRoutingContext(ctx context.Context) routing.Context {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	return &Context{
		Inbound:  session.InboundFromContext(ctx),
		Outbound: ob,
		Content:  session.ContentFromContext(ctx),
	}
}
