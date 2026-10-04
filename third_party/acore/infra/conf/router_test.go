package conf_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	_ "unsafe"

	"github.com/ImAubrey/acore/app/router"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/platform"
	"github.com/ImAubrey/acore/common/platform/filesystem"
	"github.com/ImAubrey/acore/common/serial"
	. "github.com/ImAubrey/acore/infra/conf"
	"google.golang.org/protobuf/proto"
)

func getAssetPath(file string) (string, error) {
	path := platform.GetAssetLocation(file)
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		path := filepath.Join("..", "..", "resources", file)
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			return "", fmt.Errorf("can't find %s in standard asset locations or {project_root}/resources", file)
		}
		if err != nil {
			return "", fmt.Errorf("can't stat %s: %v", path, err)
		}
		return path, nil
	}
	if err != nil {
		return "", fmt.Errorf("can't stat %s: %v", path, err)
	}

	return path, nil
}

func TestToCidrList(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-")
	if err != nil {
		t.Fatalf("can't create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	geoipPath, err := getAssetPath("geoip.dat")
	if err != nil {
		t.Fatal(err)
	}

	common.Must(filesystem.CopyFile(filepath.Join(tempDir, "geoip.dat"), geoipPath))
	common.Must(filesystem.CopyFile(filepath.Join(tempDir, "geoiptestrouter.dat"), geoipPath))

	os.Setenv("acore.location.asset", tempDir)
	defer os.Unsetenv("acore.location.asset")

	ips := StringList([]string{
		"geoip:us",
		"geoip:cn",
		"geoip:!cn",
		"ext:geoiptestrouter.dat:!cn",
		"ext:geoiptestrouter.dat:ca",
		"ext-ip:geoiptestrouter.dat:!cn",
		"ext-ip:geoiptestrouter.dat:!ca",
	})

	_, err = ToCidrList(ips)
	if err != nil {
		t.Fatalf("Failed to parse geoip list, got %s", err)
	}

	custom, err := ToCidrList(StringList([]string{"!0.0.0.0/0", "10.0.0.0/8"}))
	if err != nil {
		t.Fatalf("Failed to parse custom cidr list with reverse, got %s", err)
	}
	if len(custom) != 2 {
		t.Fatalf("Expect custom cidr list to create 2 GeoIP entries, got %d", len(custom))
	}
	var foundPos, foundNeg bool
	for _, g := range custom {
		if len(g.Cidr) != 1 {
			t.Fatalf("Expect each GeoIP entry to contain 1 CIDR, got %d", len(g.Cidr))
		}
		cidr := g.Cidr[0]
		switch {
		case g.ReverseMatch:
			if cidr.Prefix != 0 || len(cidr.Ip) != 4 || cidr.Ip[0] != 0 || cidr.Ip[1] != 0 || cidr.Ip[2] != 0 || cidr.Ip[3] != 0 {
				t.Fatalf("Unexpected reverse CIDR: %+v", cidr)
			}
			foundNeg = true
		default:
			if cidr.Prefix != 8 || len(cidr.Ip) != 4 || cidr.Ip[0] != 10 || cidr.Ip[1] != 0 || cidr.Ip[2] != 0 || cidr.Ip[3] != 0 {
				t.Fatalf("Unexpected CIDR: %+v", cidr)
			}
			foundPos = true
		}
	}
	if !foundPos || !foundNeg {
		t.Fatalf("Expected both positive and reverse CIDR entries to be present, pos: %v, neg: %v", foundPos, foundNeg)
	}
}

func TestRouterConfig(t *testing.T) {
	createParser := func() func(string) (proto.Message, error) {
		return func(s string) (proto.Message, error) {
			config := new(RouterConfig)
			if err := json.Unmarshal([]byte(s), config); err != nil {
				return nil, err
			}
			return config.Build()
		}
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"domainStrategy": "AsIs",
				"rules": [
					{
						"domain": [
							"baidu.com",
							"qq.com"
						],
						"destination": "direct"
					},
					{
						"ip": [
							"10.0.0.0/8",
							"::1/128"
						],
						"outboundTag": "test"
					},{
						"port": "53, 443, 1000-2000",
						"outboundTag": "test"
					},{
						"port": 123,
						"outboundTag": "test"
					}
				],
				"balancers": [
					{
						"tag": "b1",
						"selector": ["test"],
						"fallbackTag": "fall"
					},
					{
						"tag": "b2",
						"selector": ["test"],
						"strategy": {
							"type": "leastload",
							"settings": {
								"healthCheck": {
									"interval": "5m0s",
									"sampling": 2,
									"timeout": "5s",
									"destination": "dest",
									"connectivity": "conn"
								},
								"costs": [
									{
										"regexp": true,
										"match": "\\d+(\\.\\d+)",
										"value": 5
									}
								],
								"baselines": ["400ms", "600ms"],
								"expected": 6,
								"maxRTT": "1000ms",
								"tolerance": 0.5
							}
						},
						"fallbackTag": "fall"
					}
				]
			}`,
			Parser: createParser(),
			Output: &router.Config{
				DomainStrategy: router.Config_AsIs,
				BalancingRule: []*router.BalancingRule{
					{
						Tag:              "b1",
						OutboundSelector: []string{"test"},
						Strategy:         "random",
						FallbackTag:      "fall",
					},
					{
						Tag:              "b2",
						OutboundSelector: []string{"test"},
						Strategy:         "leastload",
						StrategySettings: serial.ToTypedMessage(&router.StrategyLeastLoadConfig{
							Costs: []*router.StrategyWeight{
								{
									Regexp: true,
									Match:  "\\d+(\\.\\d+)",
									Value:  5,
								},
							},
							Baselines: []int64{
								int64(time.Duration(400) * time.Millisecond),
								int64(time.Duration(600) * time.Millisecond),
							},
							Expected:  6,
							MaxRTT:    int64(time.Duration(1000) * time.Millisecond),
							Tolerance: 0.5,
						}),
						FallbackTag: "fall",
					},
				},
				Rule: []*router.RoutingRule{
					{
						Domain: []*router.Domain{
							{
								Type:  router.Domain_Plain,
								Value: "baidu.com",
							},
							{
								Type:  router.Domain_Plain,
								Value: "qq.com",
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
					{
						Geoip: []*router.GeoIP{
							{
								Cidr: []*router.CIDR{
									{
										Ip:     []byte{10, 0, 0, 0},
										Prefix: 8,
									},
									{
										Ip:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
										Prefix: 128,
									},
								},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "test",
						},
					},
					{
						PortList: &net.PortList{
							Range: []*net.PortRange{
								{From: 53, To: 53},
								{From: 443, To: 443},
								{From: 1000, To: 2000},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "test",
						},
					},
					{
						PortList: &net.PortList{
							Range: []*net.PortRange{
								{From: 123, To: 123},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "test",
						},
					},
				},
			},
		},
		{
			Input: `{
				"domainStrategy": "IPIfNonMatch",
				"rules": [
					{
						"domain": [
							"baidu.com",
							"qq.com"
						],
						"outboundTag": "direct"
					},
					{
						"ip": [
							"10.0.0.0/8",
							"::1/128"
						],
						"outboundTag": "test"
					}
				]
			}`,
			Parser: createParser(),
			Output: &router.Config{
				DomainStrategy: router.Config_IpIfNonMatch,
				Rule: []*router.RoutingRule{
					{
						Domain: []*router.Domain{
							{
								Type:  router.Domain_Plain,
								Value: "baidu.com",
							},
							{
								Type:  router.Domain_Plain,
								Value: "qq.com",
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
					{
						Geoip: []*router.GeoIP{
							{
								Cidr: []*router.CIDR{
									{
										Ip:     []byte{10, 0, 0, 0},
										Prefix: 8,
									},
									{
										Ip:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
										Prefix: 128,
									},
								},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "test",
						},
					},
				},
			},
		},
		{
			Input: `{
				"domainRecover": "IPReDisCover",
				"rules": [
					{
						"outboundTag": "direct",
						"network": "tcp"
					}
				]
			}`,
			Parser: createParser(),
			Output: &router.Config{
				DomainStrategy: router.Config_AsIs,
				Rule: []*router.RoutingRule{
					{
						Networks: []net.Network{net.Network_TCP},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
					{
						InboundTag: []string{router.InternalDomainRecoverInboundTag},
						Attributes: map[string]string{
							router.InternalDomainRecoverAttr: "iprediscover",
						},
					},
				},
			},
		},
	})
}

func TestRouterConfigVlessRouteQuickTarget(t *testing.T) {
	config := new(RouterConfig)
	err := json.Unmarshal([]byte(`{
		"rules": [
			{
				"ruleTag": "mark-vless",
				"vlessRoute": ["53:direct", "443,1000-1002:proxy"]
			}
		]
	}`), config)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	built, err := config.Build()
	if err != nil {
		t.Fatalf("failed to build config: %v", err)
	}

	if len(built.Rule) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(built.Rule))
	}

	rule := built.Rule[0]
	if rule.GetTag() != "" {
		t.Fatalf("expected quick target rule to have no fixed destination, got %q", rule.GetTag())
	}
	if rule.GetRuleTag() != "mark-vless" {
		t.Fatalf("expected ruleTag mark-vless, got %q", rule.GetRuleTag())
	}
	if rule.GetVlessRouteList() != nil {
		t.Fatalf("expected quick target rule to omit vlessRouteList, got %+v", rule.GetVlessRouteList())
	}

	rawAttr := rule.Attributes[router.InternalVlessRouteTargetAttr]
	if rawAttr == "" {
		t.Fatal("expected internal vlessRoute quick target attribute to be populated")
	}

	var targets []struct {
		Ranges []struct {
			From uint32 `json:"from"`
			To   uint32 `json:"to"`
		} `json:"ranges"`
		Destination string `json:"destination"`
	}
	if err := json.Unmarshal([]byte(rawAttr), &targets); err != nil {
		t.Fatalf("failed to decode internal quick targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 quick targets, got %d", len(targets))
	}
	if targets[0].Destination != "direct" || len(targets[0].Ranges) != 1 || targets[0].Ranges[0].From != 53 || targets[0].Ranges[0].To != 53 {
		t.Fatalf("unexpected first quick target: %+v", targets[0])
	}
	if targets[1].Destination != "proxy" || len(targets[1].Ranges) != 2 {
		t.Fatalf("unexpected second quick target: %+v", targets[1])
	}
	if targets[1].Ranges[0].From != 443 || targets[1].Ranges[0].To != 443 {
		t.Fatalf("unexpected second quick target first range: %+v", targets[1].Ranges[0])
	}
	if targets[1].Ranges[1].From != 1000 || targets[1].Ranges[1].To != 1002 {
		t.Fatalf("unexpected second quick target second range: %+v", targets[1].Ranges[1])
	}
}

func TestRouterConfigVlessRouteQuickTargetRejectsFixedDestination(t *testing.T) {
	config := new(RouterConfig)
	err := json.Unmarshal([]byte(`{
		"rules": [
			{
				"destination": "direct",
				"vlessRoute": ["53:proxy"]
			}
		]
	}`), config)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	if _, err := config.Build(); err == nil {
		t.Fatal("expected vlessRoute quick target rule with destination to be rejected")
	}
}
