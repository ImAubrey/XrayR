package dispatcher

import (
	"context"
	"regexp"
	"sync"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/firewall"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/policy"
	"github.com/ImAubrey/acore/features/routing"
	"github.com/ImAubrey/acore/features/stats"
)

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ohm    outbound.Manager
	router routing.Router
	fw     firewall.Manager
	policy policy.Manager
	stats  stats.Manager
	fdns   dns.FakeDNSEngine
	dns    dns.Client
	ct     conntrack.Manager

	// Cache compiled exclude-domain regex patterns from sniffing config.
	excludeDomainRegexCache sync.Map // map[string]compiledExcludeDomainRegex
}

type compiledExcludeDomainRegex struct {
	re  *regexp.Regexp
	bad bool
}

type sniffingProtocolChecker interface {
	ShouldSniffProtocol(protocol string) bool
}

type sniffingProtocolContextChecker interface {
	ShouldSniffProtocolForContext(protocol string, ctx routing.Context) bool
}

type ja4TagLookupRouter interface {
	LookupJA4Tag(fingerprint string) string
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, fw firewall.Manager, pm policy.Manager, sm stats.Manager, dc dns.Client, cm conntrack.Manager) error {
			core.OptionalFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				d.fdns = fdns
			})
			return d.Init(config.(*Config), om, router, fw, pm, sm, dc, cm)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, fw firewall.Manager, pm policy.Manager, sm stats.Manager, dc dns.Client, cm conntrack.Manager) error {
	d.ohm = om
	d.router = router
	d.fw = fw
	d.policy = pm
	d.stats = sm
	d.dns = dc
	d.ct = cm
	return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error { return nil }
