package router

import (
	"context"
	"sort"
	"strings"
	sync "sync"

	"github.com/ImAubrey/acore/app/observatory"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/dice"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/extension"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
)

type BalancingStrategy interface {
	PickOutbound([]string) string
}

type BalancingPrincipleTarget interface {
	GetPrincipleTarget([]string) []string
}

type outboundStatusChecker interface {
	OutboundStatus(tag string) (alive bool, known bool)
}

type RoundRobinStrategy struct {
	FallbackTag string

	ctx         context.Context
	observatory extension.Observatory
	mu          sync.Mutex
	index       int
}

func (s *RoundRobinStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	if len(s.FallbackTag) > 0 {
		common.Must(core.RequireFeatures(s.ctx, func(observatory extension.Observatory) error {
			s.observatory = observatory
			return nil
		}))
	}
}

func (s *RoundRobinStrategy) GetPrincipleTarget(strings []string) []string {
	return strings
}

func (s *RoundRobinStrategy) PickOutbound(tags []string) string {
	if s.observatory != nil {
		observeReport, err := s.observatory.GetObservation(s.ctx)
		if err == nil {
			aliveTags := make([]string, 0)
			if result, ok := observeReport.(*observatory.ObservationResult); ok {
				status := result.Status
				statusMap := make(map[string]*observatory.OutboundStatus)
				for _, outboundStatus := range status {
					statusMap[outboundStatus.OutboundTag] = outboundStatus
				}
				for _, candidate := range tags {
					if outboundStatus, found := statusMap[candidate]; found {
						if outboundStatus.Alive {
							aliveTags = append(aliveTags, candidate)
						}
					} else {
						// unfound candidate is considered alive
						aliveTags = append(aliveTags, candidate)
					}
				}
				tags = aliveTags
			}
		}
	}

	n := len(tags)
	if n == 0 {
		// no available candidates
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tag := tags[s.index%n]
	s.index = (s.index + 1) % n
	return tag
}

type Balancer struct {
	selectors       []string
	strategy        BalancingStrategy
	strategyName    string
	ohm             outbound.Manager
	fallbackTag     string
	orderedSelector bool
	tag             string
	balancers       map[string]*Balancer

	override override
}

func (b *Balancer) setRegistry(tag string, balancers map[string]*Balancer) {
	b.tag = tag
	b.balancers = balancers
}

func (b *Balancer) isBalancerTag(tag string) bool {
	if b == nil || tag == "" || b.balancers == nil {
		return false
	}
	_, ok := b.balancers[tag]
	return ok
}

func (b *Balancer) StrategyName() string {
	if b.strategyName != "" {
		return b.strategyName
	}
	switch b.strategy.(type) {
	case *SelectorStrategy:
		return "selector"
	case *LeastPingStrategy:
		return "leastping"
	case *RoundRobinStrategy:
		return "roundrobin"
	case *LeastLoadStrategy:
		return "leastload"
	case *RandomStrategy:
		return "random"
	default:
		return "unknown"
	}
}

// PickOutbound picks the tag of a outbound
func (b *Balancer) PickOutbound() (string, error) {
	visited := make(map[string]struct{})
	if b.tag != "" {
		visited[b.tag] = struct{}{}
	}
	return b.pickOutboundWithVisited(visited)
}

func (b *Balancer) pickOutboundWithVisited(visited map[string]struct{}) (string, error) {
	candidates, err := b.selectOutboundsWithVisited(visited)
	if err != nil {
		return "", err
	}
	var tag string
	if o := b.override.Get(); o != "" {
		resolved, err := b.resolveDestination(o, visited)
		if err != nil {
			return "", err
		}
		if b.strategyName == "selector" && b.fallbackTag != "" {
			if checker, ok := b.strategy.(outboundStatusChecker); ok {
				alive, known := checker.OutboundStatus(resolved)
				if known && !alive {
					fallback, err := b.resolveFallbackDestination(visited)
					if err != nil {
						return "", err
					}
					return fallback, nil
				}
			}
		}
		tag = resolved
	} else {
		if b.strategyName == "fallback" {
			tag, err = b.pickFallbackStrategyOutbound(visited)
			if err != nil {
				return "", err
			}
		} else {
			tag = b.strategy.PickOutbound(candidates)
		}
		if tag == "" && b.fallbackTag != "" && b.strategyName != "selector" && b.strategyName != "fallback" {
			tag, err = b.resolveFallbackDestination(visited)
			if err != nil {
				return "", err
			}
		}
	}
	if tag == "" {
		// will use default handler
		return "", errors.New("balancing strategy returns empty tag")
	}
	return tag, nil
}

func (b *Balancer) resolveDestination(tag string, visited map[string]struct{}) (string, error) {
	if tag == "" || !b.isBalancerTag(tag) {
		return tag, nil
	}
	if visited == nil {
		visited = make(map[string]struct{})
	}
	if _, ok := visited[tag]; ok {
		return "", errors.New("balancer loop detected")
	}
	visited[tag] = struct{}{}
	next := b.balancers[tag]
	if next == nil {
		delete(visited, tag)
		return tag, nil
	}
	resolved, err := next.pickOutboundWithVisited(visited)
	delete(visited, tag)
	return resolved, err
}

func (b *Balancer) selectDestinationCandidates(selector string, visited map[string]struct{}) ([]string, error) {
	if selector == "" {
		return nil, nil
	}
	if b.isBalancerTag(selector) {
		resolved, err := b.resolveDestination(selector, visited)
		if err != nil {
			return nil, err
		}
		if resolved == "" {
			return nil, nil
		}
		return []string{resolved}, nil
	}
	hs, ok := b.ohm.(outbound.HandlerSelector)
	if !ok {
		return nil, errors.New("outbound.Manager is not a HandlerSelector")
	}
	tags := hs.Select([]string{selector})
	if len(tags) == 0 {
		// Keep compatibility for explicit fallback target that is not a selector prefix.
		return []string{selector}, nil
	}
	return tags, nil
}

func (b *Balancer) pickRandomFromCandidates(tags []string, checker outboundStatusChecker) string {
	if len(tags) == 0 {
		return ""
	}
	if checker == nil {
		return tags[dice.Roll(len(tags))]
	}
	aliveOrUnknown := make([]string, 0, len(tags))
	for _, tag := range tags {
		alive, known := checker.OutboundStatus(tag)
		if !known || alive {
			aliveOrUnknown = append(aliveOrUnknown, tag)
		}
	}
	if len(aliveOrUnknown) == 0 {
		return tags[dice.Roll(len(tags))]
	}
	return aliveOrUnknown[dice.Roll(len(aliveOrUnknown))]
}

func (b *Balancer) resolveFallbackDestination(visited map[string]struct{}) (string, error) {
	fallback := strings.TrimSpace(b.fallbackTag)
	if fallback == "" {
		return "", nil
	}
	candidates, err := b.selectDestinationCandidates(fallback, visited)
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", nil
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	checker, _ := b.strategy.(outboundStatusChecker)
	return b.pickRandomFromCandidates(candidates, checker), nil
}

func (b *Balancer) pickFallbackStrategyOutbound(visited map[string]struct{}) (string, error) {
	checker, _ := b.strategy.(outboundStatusChecker)
	fallback := strings.TrimSpace(b.fallbackTag)
	fallbackCandidates, err := b.selectDestinationCandidates(fallback, visited)
	if err != nil {
		return "", err
	}
	candidates, err := b.selectOutboundsWithVisited(visited)
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", nil
	}
	picked := b.strategy.PickOutbound(candidates)
	if picked == "" || len(fallbackCandidates) <= 1 {
		return picked, nil
	}
	for _, tag := range fallbackCandidates {
		if tag == picked {
			return b.pickRandomFromCandidates(fallbackCandidates, checker), nil
		}
	}
	return picked, nil
}

func (b *Balancer) InjectContext(ctx context.Context) {
	if contextReceiver, ok := b.strategy.(extension.ContextReceiver); ok {
		contextReceiver.InjectContext(ctx)
	}
}

// SelectOutbounds select outbounds with selectors of the Balancer
func (b *Balancer) SelectOutbounds() ([]string, error) {
	visited := make(map[string]struct{})
	if b.tag != "" {
		visited[b.tag] = struct{}{}
	}
	return b.selectOutboundsWithVisited(visited)
}

// SelectPrincipleOutbounds selects display candidates for principle target consumers.
// Nested balancer selectors are preserved as balancer tags.
func (b *Balancer) SelectPrincipleOutbounds() ([]string, error) {
	return b.selectPrincipleOutbounds()
}

func (b *Balancer) selectOutboundsWithVisited(visited map[string]struct{}) ([]string, error) {
	hs, ok := b.ohm.(outbound.HandlerSelector)
	if !ok {
		return nil, errors.New("outbound.Manager is not a HandlerSelector")
	}
	if len(b.selectors) == 0 {
		return nil, errors.New("empty selector list")
	}
	if !b.orderedSelector {
		outboundSelectors := make([]string, 0, len(b.selectors))
		balancerSelectors := make([]string, 0)
		for _, selector := range b.selectors {
			if selector == "" {
				continue
			}
			if b.isBalancerTag(selector) {
				balancerSelectors = append(balancerSelectors, selector)
				continue
			}
			outboundSelectors = append(outboundSelectors, selector)
		}
		tags := []string{}
		if len(outboundSelectors) > 0 {
			tags = hs.Select(outboundSelectors)
		}
		seen := make(map[string]struct{}, len(tags))
		for _, tag := range tags {
			seen[tag] = struct{}{}
		}
		for _, selector := range balancerSelectors {
			resolved, err := b.resolveDestination(selector, visited)
			if err != nil {
				return nil, err
			}
			if resolved == "" {
				continue
			}
			if _, exists := seen[resolved]; exists {
				continue
			}
			seen[resolved] = struct{}{}
			tags = append(tags, resolved)
		}
		sort.Strings(tags)
		return tags, nil
	}
	tags := make([]string, 0)
	seen := make(map[string]struct{})
	for _, selector := range b.selectors {
		if selector == "" {
			continue
		}
		if b.isBalancerTag(selector) {
			resolved, err := b.resolveDestination(selector, visited)
			if err != nil {
				return nil, err
			}
			if resolved == "" {
				continue
			}
			if _, exists := seen[resolved]; exists {
				continue
			}
			seen[resolved] = struct{}{}
			tags = append(tags, resolved)
			continue
		}
		list := hs.Select([]string{selector})
		for _, tag := range list {
			if _, exists := seen[tag]; exists {
				continue
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}
	}
	return tags, nil
}

func (b *Balancer) selectPrincipleOutbounds() ([]string, error) {
	hs, ok := b.ohm.(outbound.HandlerSelector)
	if !ok {
		return nil, errors.New("outbound.Manager is not a HandlerSelector")
	}
	if len(b.selectors) == 0 {
		return nil, errors.New("empty selector list")
	}
	if !b.orderedSelector {
		tags := make([]string, 0)
		seen := make(map[string]struct{})
		for _, selector := range b.selectors {
			if selector == "" {
				continue
			}
			if b.isBalancerTag(selector) {
				if _, exists := seen[selector]; exists {
					continue
				}
				seen[selector] = struct{}{}
				tags = append(tags, selector)
				continue
			}
			list := b.selectOutboundsForUI(selector, hs)
			for _, tag := range list {
				if _, exists := seen[tag]; exists {
					continue
				}
				seen[tag] = struct{}{}
				tags = append(tags, tag)
			}
		}
		return tags, nil
	}
	tags := make([]string, 0)
	seen := make(map[string]struct{})
	for _, selector := range b.selectors {
		if selector == "" {
			continue
		}
		if b.isBalancerTag(selector) {
			if _, exists := seen[selector]; exists {
				continue
			}
			seen[selector] = struct{}{}
			tags = append(tags, selector)
			continue
		}
		list := b.selectOutboundsForUI(selector, hs)
		for _, tag := range list {
			if _, exists := seen[tag]; exists {
				continue
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}
	}
	return tags, nil
}

func (b *Balancer) selectOutboundsForUI(selector string, hs outbound.HandlerSelector) []string {
	if selector == "" {
		return nil
	}

	if b.ohm != nil {
		handlers := b.ohm.ListHandlers(context.Background())
		if len(handlers) > 0 {
			out := make([]string, 0)
			for _, handler := range handlers {
				if handler == nil {
					continue
				}
				tag := handler.Tag()
				if tag == "" {
					continue
				}
				if strings.HasPrefix(tag, selector) {
					out = append(out, tag)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}

	return hs.Select([]string{selector})
}

// GetPrincipleTarget implements routing.BalancerPrincipleTarget
func (r *Router) GetPrincipleTarget(tag string) ([]string, error) {
	if b, ok := r.balancers[tag]; ok {
		if s, ok := b.strategy.(BalancingPrincipleTarget); ok {
			candidates, err := b.SelectPrincipleOutbounds()
			if err != nil {
				return nil, errors.New("unable to select outbounds").Base(err)
			}
			return s.GetPrincipleTarget(candidates), nil
		}
		return nil, errors.New("unsupported GetPrincipleTarget")
	}
	return nil, errors.New("cannot find tag")
}

// SetOverrideTarget implements routing.BalancerOverrider
func (r *Router) SetOverrideTarget(tag, target string) error {
	if b, ok := r.balancers[tag]; ok {
		b.override.Put(target)
		return nil
	}
	return errors.New("cannot find tag")
}

// GetOverrideTarget implements routing.BalancerOverrider
func (r *Router) GetOverrideTarget(tag string) (string, error) {
	if b, ok := r.balancers[tag]; ok {
		return b.override.Get(), nil
	}
	return "", errors.New("cannot find tag")
}

// GetBalancerInfo implements routing.BalancerInfoProvider.
func (r *Router) GetBalancerInfo(tag string) (routing.BalancerInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if b, ok := r.balancers[tag]; ok {
		return routing.BalancerInfo{
			Tag:         tag,
			Strategy:    b.StrategyName(),
			FallbackTag: b.fallbackTag,
		}, nil
	}
	return routing.BalancerInfo{}, errors.New("cannot find tag")
}

// ListBalancerTags implements routing.BalancerLister.
func (r *Router) ListBalancerTags() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.balancers) == 0 {
		return []string{}
	}
	tags := make([]string, 0, len(r.balancers))
	seen := make(map[string]struct{}, len(r.balancers))
	for _, tag := range r.balancerOrder {
		if _, ok := r.balancers[tag]; !ok {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	extras := make([]string, 0)
	for tag := range r.balancers {
		if _, ok := seen[tag]; ok {
			continue
		}
		extras = append(extras, tag)
	}
	sort.Strings(extras)
	tags = append(tags, extras...)
	return tags
}

// GetBalancerStrategy exposes the balancer strategy for UI and metrics consumers.
func (r *Router) GetBalancerStrategy(tag string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if b, ok := r.balancers[tag]; ok {
		return b.StrategyName(), nil
	}
	return "", errors.New("cannot find tag")
}

// ResolveDestination resolves a destination name to an outbound tag.
func (r *Router) ResolveDestination(destination string) (string, error) {
	if destination == "" {
		return "", errors.New("empty destination")
	}
	r.mu.Lock()
	balancer := r.balancers[destination]
	ohm := r.ohm
	r.mu.Unlock()

	if balancer != nil {
		return balancer.PickOutbound()
	}
	if ohm != nil && ohm.GetHandler(destination) == nil {
		return "", errors.New("destination ", destination, " not found")
	}
	return destination, nil
}
