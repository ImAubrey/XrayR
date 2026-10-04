package all

import (
	// The following are necessary as they register handlers in their init functions.

	_ "github.com/ImAubrey/acore/app/proxyman/inbound"
	_ "github.com/ImAubrey/acore/app/proxyman/outbound"

	// Required features. Can't remove unless there is replacements.
	// _ "github.com/ImAubrey/acore/app/dispatcher"
	_ "github.com/ImAubrey/acore-backend/app/mydispatcher"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/ImAubrey/acore/app/commander"
	_ "github.com/ImAubrey/acore/app/log/command"
	_ "github.com/ImAubrey/acore/app/proxyman/command"
	_ "github.com/ImAubrey/acore/app/startup/command"
	_ "github.com/ImAubrey/acore/app/stats/command"

	// Developer preview services.
	_ "github.com/ImAubrey/acore/app/observatory/command"

	// Other optional features.
	_ "github.com/ImAubrey/acore/app/dns"
	_ "github.com/ImAubrey/acore/app/dns/fakedns"
	_ "github.com/ImAubrey/acore/app/firewall"
	_ "github.com/ImAubrey/acore/app/log"
	_ "github.com/ImAubrey/acore/app/metrics"
	_ "github.com/ImAubrey/acore/app/policy"
	_ "github.com/ImAubrey/acore/app/reverse"
	_ "github.com/ImAubrey/acore/app/router"
	_ "github.com/ImAubrey/acore/app/stats"

	// Fix dependency cycle caused by core import in internet package.
	_ "github.com/ImAubrey/acore/transport/internet/tagged/taggedimpl"

	// Developer preview features.
	_ "github.com/ImAubrey/acore/app/observatory"

	// Inbound and outbound proxies.
	_ "github.com/ImAubrey/acore/proxy/blackhole"
	_ "github.com/ImAubrey/acore/proxy/dns"
	_ "github.com/ImAubrey/acore/proxy/dokodemo"
	_ "github.com/ImAubrey/acore/proxy/freedom"
	_ "github.com/ImAubrey/acore/proxy/http"
	_ "github.com/ImAubrey/acore/proxy/hysteria"
	_ "github.com/ImAubrey/acore/proxy/loopback"
	_ "github.com/ImAubrey/acore/proxy/shadowsocks"
	_ "github.com/ImAubrey/acore/proxy/shadowsocks_2022"
	_ "github.com/ImAubrey/acore/proxy/socks"
	_ "github.com/ImAubrey/acore/proxy/trojan"
	_ "github.com/ImAubrey/acore/proxy/vless/inbound"
	_ "github.com/ImAubrey/acore/proxy/vless/outbound"
	_ "github.com/ImAubrey/acore/proxy/vmess/inbound"
	_ "github.com/ImAubrey/acore/proxy/vmess/outbound"
	_ "github.com/ImAubrey/acore/proxy/wireguard"

	// Transports
	_ "github.com/ImAubrey/acore/transport/internet/axpath"
	_ "github.com/ImAubrey/acore/transport/internet/grpc"
	_ "github.com/ImAubrey/acore/transport/internet/httpupgrade"
	_ "github.com/ImAubrey/acore/transport/internet/hysteria"
	_ "github.com/ImAubrey/acore/transport/internet/kcp"
	_ "github.com/ImAubrey/acore/transport/internet/reality"
	_ "github.com/ImAubrey/acore/transport/internet/splithttp"
	_ "github.com/ImAubrey/acore/transport/internet/tcp"
	_ "github.com/ImAubrey/acore/transport/internet/tls"
	_ "github.com/ImAubrey/acore/transport/internet/udp"
	_ "github.com/ImAubrey/acore/transport/internet/websocket"

	// Transport headers
	_ "github.com/ImAubrey/acore/transport/internet/headers/dns"
	_ "github.com/ImAubrey/acore/transport/internet/headers/http"
	_ "github.com/ImAubrey/acore/transport/internet/headers/noop"
	_ "github.com/ImAubrey/acore/transport/internet/headers/srtp"
	_ "github.com/ImAubrey/acore/transport/internet/headers/tls"
	_ "github.com/ImAubrey/acore/transport/internet/headers/utp"
	_ "github.com/ImAubrey/acore/transport/internet/headers/wechat"
	_ "github.com/ImAubrey/acore/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/ImAubrey/acore/main/json"
	_ "github.com/ImAubrey/acore/main/toml"
	_ "github.com/ImAubrey/acore/main/yaml"

	// Load config from file or http(s)
	_ "github.com/ImAubrey/acore/main/confloader/external"

	// Commands
	_ "github.com/ImAubrey/acore/main/commands/all"
)
