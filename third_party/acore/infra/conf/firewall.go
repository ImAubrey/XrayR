package conf

import (
	"encoding/json"
	"strings"

	firewallapp "github.com/ImAubrey/acore/app/firewall"
	routerapp "github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common/errors"
)

type FirewallLimitConfig struct {
	Key            string `json:"key"`
	CountBy        string `json:"countBy"`
	Mode           string `json:"mode"`
	MaxConnections uint32 `json:"maxConnections"`
	WindowSeconds  uint32 `json:"windowSeconds"`
}

type FirewallConfig struct {
	RuleList []json.RawMessage `json:"rules"`
}

type rawFirewallRule struct {
	RouterRule
	Action string               `json:"action"`
	Limit  *FirewallLimitConfig `json:"limit"`
}

func (c *FirewallConfig) Build() (*firewallapp.Config, error) {
	cfg := &firewallapp.Config{
		Rule: make([]*firewallapp.Rule, 0, len(c.RuleList)),
	}
	for _, rawRule := range c.RuleList {
		rule, err := ParseFirewallRule(rawRule)
		if err != nil {
			return nil, err
		}
		cfg.Rule = append(cfg.Rule, rule)
	}
	return cfg, nil
}

func ParseFirewallRule(msg json.RawMessage) (*firewallapp.Rule, error) {
	raw := new(rawFirewallRule)
	if err := json.Unmarshal(msg, raw); err != nil {
		return nil, errors.New("invalid firewall rule").Base(err)
	}

	if !raw.Destination.IsEmpty() || strings.TrimSpace(raw.OutboundTag) != "" || strings.TrimSpace(raw.BalancerTag) != "" {
		return nil, errors.New("firewall rule does not support destination/outboundTag/balancerTag")
	}

	match, err := parseFieldRuleWithOptions(msg, true)
	if err != nil {
		return nil, errors.New("invalid firewall field rule").Base(err)
	}
	if match.GetTag() != "" || match.GetBalancingTag() != "" {
		return nil, errors.New("firewall rule does not support route targets")
	}
	if match.GetReLookup() {
		return nil, errors.New("firewall rule does not support reLookup")
	}

	action, err := parseFirewallAction(raw.Action, match.GetRuleTag() != "")
	if err != nil {
		return nil, err
	}

	rule := &firewallapp.Rule{
		Match:  match,
		Action: action,
	}

	if action == firewallapp.Rule_Limit {
		if raw.Limit == nil {
			return nil, errors.New("firewall limit action requires limit config")
		}
		limitKey := raw.Limit.Key
		if strings.TrimSpace(limitKey) == "" {
			limitKey = raw.Limit.CountBy
		}
		key, err := parseFirewallLimitKey(limitKey)
		if err != nil {
			return nil, err
		}
		if raw.Limit.MaxConnections == 0 {
			return nil, errors.New("firewall limit.maxConnections must be greater than 0")
		}
		mode, err := parseFirewallLimitMode(raw.Limit.Mode)
		if err != nil {
			return nil, err
		}
		switch mode {
		case firewallapp.ConnectionLimit_NewConnections:
			if raw.Limit.WindowSeconds == 0 {
				return nil, errors.New("firewall limit.windowSeconds must be greater than 0 when mode=newConnections")
			}
		default:
			if raw.Limit.WindowSeconds != 0 {
				return nil, errors.New("firewall limit.windowSeconds is only valid when mode=newConnections")
			}
		}
		if err := validateFirewallPrefixLimit(key, match); err != nil {
			return nil, err
		}
		rule.Limit = &firewallapp.ConnectionLimit{
			Key:            key,
			MaxConnections: raw.Limit.MaxConnections,
			Mode:           mode,
			WindowSeconds:  raw.Limit.WindowSeconds,
		}
	} else if raw.Limit != nil {
		return nil, errors.New("firewall limit config is only valid when action=limit")
	}

	return rule, nil
}

func parseFirewallAction(raw string, hasRuleTag bool) (firewallapp.Rule_Action, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		if hasRuleTag {
			return firewallapp.Rule_Mark, nil
		}
		return firewallapp.Rule_Mark, errors.New("firewall rule must set action when ruleTag is empty")
	case "mark":
		if !hasRuleTag {
			return firewallapp.Rule_Mark, errors.New("firewall mark action requires ruleTag")
		}
		return firewallapp.Rule_Mark, nil
	case "allow", "accept":
		return firewallapp.Rule_Allow, nil
	case "block", "deny", "reject":
		return firewallapp.Rule_Block, nil
	case "limit":
		return firewallapp.Rule_Limit, nil
	default:
		return firewallapp.Rule_Mark, errors.New("unsupported firewall action: ", raw)
	}
}

func parseFirewallLimitKey(raw string) (firewallapp.ConnectionLimit_Key, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "srcip", "sourceip", "source_ip":
		return firewallapp.ConnectionLimit_SrcIp, nil
	case "dstip", "destinationip", "destination_ip":
		return firewallapp.ConnectionLimit_DstIp, nil
	case "srcdstip", "sourcedestinationip", "source_destination_ip", "src-dst-ip":
		return firewallapp.ConnectionLimit_SrcDstIp, nil
	case "srcprefix", "sourceprefix", "source_prefix", "src-prefix":
		return firewallapp.ConnectionLimit_SrcPrefix, nil
	case "dstprefix", "destinationprefix", "destination_prefix", "dst-prefix":
		return firewallapp.ConnectionLimit_DstPrefix, nil
	default:
		return firewallapp.ConnectionLimit_SrcIp, errors.New("unsupported firewall limit key: ", raw)
	}
}

func parseFirewallLimitMode(raw string) (firewallapp.ConnectionLimit_Mode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "active", "activeconnections", "active_connections":
		return firewallapp.ConnectionLimit_ActiveConnections, nil
	case "new", "newconnections", "new_connections":
		return firewallapp.ConnectionLimit_NewConnections, nil
	default:
		return firewallapp.ConnectionLimit_ActiveConnections, errors.New("unsupported firewall limit mode: ", raw)
	}
}

func validateFirewallPrefixLimit(key firewallapp.ConnectionLimit_Key, match *routerapp.RoutingRule) error {
	if match == nil {
		return nil
	}
	switch key {
	case firewallapp.ConnectionLimit_SrcPrefix:
		return validateFirewallPrefixGeoIPs(match.GetSourceGeoip(), "source/sourceIP")
	case firewallapp.ConnectionLimit_DstPrefix:
		return validateFirewallPrefixGeoIPs(match.GetGeoip(), "ip")
	default:
		return nil
	}
}

func validateFirewallPrefixGeoIPs(geoips []*routerapp.GeoIP, fieldName string) error {
	if len(geoips) == 0 {
		return errors.New("firewall prefix limit requires explicit ", fieldName, " CIDR entries")
	}
	foundCIDR := false
	for _, geoip := range geoips {
		if geoip == nil {
			continue
		}
		if geoip.GetReverseMatch() {
			return errors.New("firewall prefix limit does not support reverse CIDR in ", fieldName)
		}
		if strings.TrimSpace(geoip.GetCountryCode()) != "" {
			return errors.New("firewall prefix limit requires explicit CIDR entries in ", fieldName)
		}
		if len(geoip.GetCidr()) > 0 {
			foundCIDR = true
		}
	}
	if !foundCIDR {
		return errors.New("firewall prefix limit requires explicit ", fieldName, " CIDR entries")
	}
	return nil
}
