package conf_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/serial"
	. "github.com/ImAubrey/acore/infra/conf"
	"github.com/ImAubrey/acore/proxy/shadowsocks"
)

func TestShadowsocksServerConfigParsing(t *testing.T) {
	creator := func() Buildable {
		return new(ShadowsocksServerConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"method": "aes-256-GCM",
				"password": "acore-password"
			}`,
			Parser: loadJSON(creator),
			Output: &shadowsocks.ServerConfig{
				Users: []*protocol.User{{
					Account: serial.ToTypedMessage(&shadowsocks.Account{
						CipherType: shadowsocks.CipherType_AES_256_GCM,
						Password:   "acore-password",
					}),
				}},
				Network: []net.Network{net.Network_TCP},
			},
		},
	})
}
