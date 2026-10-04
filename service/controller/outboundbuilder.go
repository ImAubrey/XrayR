package controller

import (
	"encoding/json"
	"fmt"

	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/infra/conf"

	"github.com/ImAubrey/acore-backend/api"
)

// OutboundBuilder build freedom outbound config for addOutbound
func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = tag

	// SendThrough setting
	if config.SendIP != "" {
		outboundDetourConfig.SendThrough = conf.SendThroughConfig{Raw: &config.SendIP}
	}

	// Freedom Protocol setting
	var domainStrategy = "Asis"
	if config.EnableDNS {
		if config.DNSType != "" {
			domainStrategy = config.DNSType
		} else {
			domainStrategy = "UseIP"
		}
	}
	proxySetting := &conf.FreedomConfig{
		DomainStrategy: domainStrategy,
		PreConKeep:     json.RawMessage("false"),
	}
	// Used for Shadowsocks-Plugin
	if api.CanonicalNodeType(nodeInfo.NodeType, nodeInfo.EnableVless) == "dokodemo-door" {
		proxySetting.Redirect = fmt.Sprintf("127.0.0.1:%d", nodeInfo.Port-1)
	}
	var setting json.RawMessage
	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", nodeInfo.NodeType, err)
	}
	outboundDetourConfig.Settings = &setting
	return outboundDetourConfig.Build()
}
