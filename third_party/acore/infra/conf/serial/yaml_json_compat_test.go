package serial_test

import (
	"bytes"
	"testing"

	"github.com/ImAubrey/acore/infra/conf/serial"
	"google.golang.org/protobuf/proto"
)

func TestYAMLAndJSONLoadToSameConfig(t *testing.T) {
	jsonConfig := `{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 1080,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "freedom",
      "tag": "proxy"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "balancers": [
      {
        "tag": "round",
        "selector": [
          "proxy"
        ]
      }
    ],
    "rules": [
      {
        "type": "field",
        "domains": [
          "example.com"
        ],
        "outboundTag": "direct",
        "source": [
          "10.0.0.1"
        ],
        "ruleTag": "r1"
      },
      {
        "type": "field",
        "domain": [
          "example.org"
        ],
        "destination": {
          "tag": "proxy",
          "vlessRoute": "0xffff"
        },
        "sourceIP": [
          "10.0.0.2"
        ],
        "ruleTag": "r2"
      },
      {
        "type": "field",
        "domain": [
          "example.net"
        ],
        "balancerTag": "round",
        "ruleTag": "r3"
      }
    ]
  }
}`

	yamlConfig := `
log:
  loglevel: info
inbounds:
  - listen: 127.0.0.1
    port: 1080
    protocol: socks
    settings:
      auth: noauth
      udp: true
outbounds:
  - protocol: freedom
    tag: direct
  - protocol: freedom
    tag: proxy
routing:
  domainStrategy: AsIs
  balancers:
    - tag: round
      selector:
        - proxy
  rules:
    - type: field
      domain:
        - example.com
      destination: direct
      sourceIP:
        - 10.0.0.1
      ruleTag: r1
    - type: field
      domains:
        - example.org
      destination:
        tag: proxy
        vlessRoute: 65535
      source:
        - 10.0.0.2
      ruleTag: r2
    - type: field
      domain:
        - example.net
      balancerTag: round
      ruleTag: r3
`

	jsonPB, err := serial.LoadJSONConfig(bytes.NewReader([]byte(jsonConfig)))
	if err != nil {
		t.Fatalf("LoadJSONConfig error: %v", err)
	}
	yamlPB, err := serial.LoadYAMLConfig(bytes.NewReader([]byte(yamlConfig)))
	if err != nil {
		t.Fatalf("LoadYAMLConfig error: %v", err)
	}
	if !proto.Equal(jsonPB, yamlPB) {
		t.Fatalf("protobuf config mismatch between json and yaml")
	}
}
