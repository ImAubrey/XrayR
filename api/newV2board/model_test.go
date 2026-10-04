package newV2board

import (
	"encoding/json"
	"testing"

	"github.com/ImAubrey/acore-backend/api"
)

func TestServerConfigAcceptsStringTLSMode(t *testing.T) {
	var cfg serverConfig
	err := json.Unmarshal([]byte(`{
		"server_port": "443",
		"network": "tcp",
		"tls": "tls",
		"flow": "xtls-rprx-vision",
		"network_settings": {},
		"tls_settings": {
			"server_port": 443,
			"server_name": "example.com",
			"dest": "example.com",
			"xver": "0"
		}
	}`), &cfg)
	if err != nil {
		t.Fatal(err)
	}

	client := &APIClient{
		NodeID:      1,
		NodeType:    "V2ray",
		EnableVless: true,
	}
	nodeInfo, err := client.parseV2rayNodeResponse(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !nodeInfo.EnableTLS {
		t.Fatal("expected tls to be enabled")
	}
	if nodeInfo.TransportProtocol != "tcp" {
		t.Fatalf("expected tcp transport, got %s", nodeInfo.TransportProtocol)
	}
	if nodeInfo.VlessFlow != "xtls-rprx-vision" {
		t.Fatalf("expected vision flow, got %s", nodeInfo.VlessFlow)
	}
}

func TestVlessNodeTypeUsesVlessNetworkSettings(t *testing.T) {
	var cfg serverConfig
	err := json.Unmarshal([]byte(`{
		"server_port": 13443,
		"network": "httpupgrade",
		"tls": 0,
		"network_settings": {
			"path": "/werfdwqas55tghji87654edfvb1?ed=0",
			"headers": {
				"Host": "c.aub.ooo"
			}
		}
	}`), &cfg)
	if err != nil {
		t.Fatal(err)
	}

	client := &APIClient{
		NodeID:   14,
		NodeType: "Vless",
	}
	nodeInfo, err := client.parseV2rayNodeResponse(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !nodeInfo.EnableVless {
		t.Fatal("expected vless to be enabled for Vless node type")
	}
	if nodeInfo.Path != "/werfdwqas55tghji87654edfvb1?ed=0" {
		t.Fatalf("unexpected path: %q", nodeInfo.Path)
	}
	if nodeInfo.Host != "c.aub.ooo" {
		t.Fatalf("unexpected host: %q", nodeInfo.Host)
	}
}

func TestPanelNodeTypeMapsHysteriaToHY2(t *testing.T) {
	if got := api.CanonicalNodeType("Hysteria2", false); got != api.NodeTypeHY2 {
		t.Fatalf("expected hy2, got %s", got)
	}
}
