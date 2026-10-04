package metrics

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	routercfg "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/features/outbound"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type ruleConfigProvider interface {
	ListRuleConfigs() []*routercfg.RoutingRule
	ListBalancerConfigs() []*routercfg.BalancingRule
}

type ruleView struct {
	RuleTag     string          `json:"ruleTag,omitempty"`
	TargetTag   string          `json:"targetTag,omitempty"`
	BalancerTag string          `json:"balancerTag,omitempty"`
	Raw         json.RawMessage `json:"raw,omitempty"`
}

type balancerView struct {
	Tag         string          `json:"tag,omitempty"`
	Selectors   []string        `json:"selectors,omitempty"`
	Candidates  []string        `json:"candidates,omitempty"`
	Strategy    string          `json:"strategy,omitempty"`
	FallbackTag string          `json:"fallbackTag,omitempty"`
	Raw         json.RawMessage `json:"raw,omitempty"`
}

type rulesResponse struct {
	Rules     []ruleView     `json:"rules"`
	Balancers []balancerView `json:"balancers"`
	UpdatedAt string         `json:"updatedAt"`
}

var rulesJSON = protojson.MarshalOptions{
	UseProtoNames:   true,
	EmitUnpopulated: false,
}

var rulesOnce sync.Once

func registerRulesRoutes() {
	rulesOnce.Do(func() {
		http.HandleFunc("/rules", rulesHandler)
	})
}

func rulesHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	om, router, _ := getNodesDependencies()
	if router == nil {
		http.Error(w, "router unavailable", http.StatusServiceUnavailable)
		return
	}
	provider, ok := router.(ruleConfigProvider)
	if !ok {
		http.Error(w, "rules unavailable", http.StatusNotImplemented)
		return
	}

	var selector outbound.HandlerSelector
	if om != nil {
		selector, _ = om.(outbound.HandlerSelector)
	}

	balancerConfigs := provider.ListBalancerConfigs()
	balancerByTag := make(map[string]*routercfg.BalancingRule, len(balancerConfigs))
	for _, balancer := range balancerConfigs {
		if balancer == nil {
			continue
		}
		tag := strings.TrimSpace(balancer.GetTag())
		if tag == "" {
			continue
		}
		balancerByTag[tag] = balancer
	}

	resp := rulesResponse{
		Rules:     []ruleView{},
		Balancers: []balancerView{},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	for _, rule := range provider.ListRuleConfigs() {
		if rule == nil {
			continue
		}
		resp.Rules = append(resp.Rules, ruleView{
			RuleTag:     rule.GetRuleTag(),
			TargetTag:   rule.GetTag(),
			BalancerTag: rule.GetBalancingTag(),
			Raw:         marshalProto(rule),
		})
	}

	for _, balancer := range balancerConfigs {
		if balancer == nil {
			continue
		}
		selectors := append([]string{}, balancer.GetOutboundSelector()...)
		candidates := resolveBalancerCandidates(selectors, balancerByTag, selector)
		resp.Balancers = append(resp.Balancers, balancerView{
			Tag:         balancer.GetTag(),
			Selectors:   selectors,
			Candidates:  candidates,
			Strategy:    balancer.GetStrategy(),
			FallbackTag: balancer.GetFallbackTag(),
			Raw:         marshalProto(balancer),
		})
	}

	writeJSON(w, resp)
}

func resolveBalancerCandidates(selectors []string, balancerByTag map[string]*routercfg.BalancingRule, selector outbound.HandlerSelector) []string {
	if len(selectors) == 0 {
		return nil
	}

	prefixes := make([]string, 0, len(selectors))
	out := make([]string, 0)
	for _, raw := range selectors {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}

		// Keep nested balancers as direct candidates for UI visibility.
		// Do not recursively expand their selector tree here.
		if balancerByTag != nil {
			if nested, ok := balancerByTag[value]; ok && nested != nil {
				out = append(out, value)
				continue
			}
		}

		prefixes = append(prefixes, value)
	}

	if selector != nil && len(prefixes) > 0 {
		out = append(out, selector.Select(prefixes)...)
	}

	return uniqueSortedStrings(out)
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return nil
	}
	sort.Strings(normalized)
	out := make([]string, 0, len(normalized))
	last := ""
	for _, value := range normalized {
		if value == last {
			continue
		}
		last = value
		out = append(out, value)
	}
	return out
}

func marshalProto(msg proto.Message) json.RawMessage {
	if msg == nil {
		return nil
	}
	raw, err := rulesJSON.Marshal(msg)
	if err != nil {
		return nil
	}
	return raw
}
