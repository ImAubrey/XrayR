package routing

type BalancerOverrider interface {
	SetOverrideTarget(tag, target string) error
	GetOverrideTarget(tag string) (string, error)
}

type BalancerPrincipleTarget interface {
	GetPrincipleTarget(tag string) ([]string, error)
}

type BalancerLister interface {
	ListBalancerTags() []string
}

type BalancerInfo struct {
	Tag         string
	Strategy    string
	FallbackTag string
}

type BalancerInfoProvider interface {
	GetBalancerInfo(tag string) (BalancerInfo, error)
}

// DestinationResolver resolves a destination name to an outbound tag.
// If the destination refers to a balancer, the resolver should pick an outbound based on its strategy.
type DestinationResolver interface {
	ResolveDestination(destination string) (string, error)
}
