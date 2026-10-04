// Package controller Package generate the InboundConfig used by add inbound
package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/infra/conf"
	"github.com/go-resty/resty/v2"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	C "github.com/sagernet/sing/common"

	"github.com/ImAubrey/acore-backend/api"
)

// InboundBuilder build Inbound config for different protocol
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	inboundDetourConfig := &conf.InboundDetourConfig{}
	nodeType := api.CanonicalNodeType(nodeInfo.NodeType, nodeInfo.EnableVless)

	// Build Listen IP address
	if nodeType == "shadowsocks-plugin" {
		// Shdowsocks listen in 127.0.0.1 for safety
		inboundDetourConfig.ListenOn = &conf.Address{Address: net.ParseAddress("127.0.0.1")}
	} else if config.ListenIP != "" {
		ipAddress := net.ParseAddress(config.ListenIP)
		inboundDetourConfig.ListenOn = &conf.Address{Address: ipAddress}
	}

	// Build Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: nodeInfo.Port, To: nodeInfo.Port}},
	}
	inboundDetourConfig.PortList = portList
	// Build Tag
	inboundDetourConfig.Tag = tag
	// SniffingConfig
	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: &conf.StringList{"http", "tls", "quic", "fakedns"},
	}
	if config.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	var (
		protocol      string
		streamSetting *conf.StreamConfig
		setting       json.RawMessage
	)

	var proxySetting any
	// Build Protocol and Protocol setting
	switch nodeType {
	case "v2ray", "vmess", "vless":
		if api.IsVlessNodeType(nodeInfo.NodeType, nodeInfo.EnableVless) {
			protocol = "vless"
			// Enable fallback
			if config.EnableFallback {
				fallbackConfigs, err := buildVlessFallbacks(config.FallBackConfigs)
				if err == nil {
					proxySetting = &conf.VLessInboundConfig{
						Decryption: "none",
						Fallbacks:  fallbackConfigs,
					}
				} else {
					return nil, err
				}
			} else {
				proxySetting = &conf.VLessInboundConfig{
					Decryption: "none",
				}
			}
		} else {
			protocol = "vmess"
			proxySetting = &conf.VMessInboundConfig{}
		}
	case "trojan":
		protocol = "trojan"
		// Enable fallback
		if config.EnableFallback {
			fallbackConfigs, err := buildTrojanFallbacks(config.FallBackConfigs)
			if err == nil {
				proxySetting = &conf.TrojanServerConfig{
					Fallbacks: fallbackConfigs,
				}
			} else {
				return nil, err
			}
		} else {
			proxySetting = &conf.TrojanServerConfig{}
		}
	case "shadowsocks", "shadowsocks-plugin":
		protocol = "shadowsocks"
		cipher := strings.ToLower(nodeInfo.CypherMethod)

		proxySetting = &conf.ShadowsocksServerConfig{
			Cipher:   cipher,
			Password: nodeInfo.ServerKey, // shadowsocks2022 shareKey
		}

		proxySetting, _ := proxySetting.(*conf.ShadowsocksServerConfig)
		// shadowsocks must have a random password
		// shadowsocks2022's password == user PSK, thus should a length of string >= 32 and base64 encoder
		b := make([]byte, 32)
		rand.Read(b)
		randPasswd := hex.EncodeToString(b)
		if C.Contains(shadowaead_2022.List, cipher) {
			proxySetting.Users = append(proxySetting.Users, &conf.ShadowsocksUserConfig{
				Password: base64.StdEncoding.EncodeToString(b),
			})
		} else {
			proxySetting.Password = randPasswd
		}

		proxySetting.NetworkList = &conf.NetworkList{"tcp", "udp"}
		proxySetting.IVCheck = true
		if config.DisableIVCheck {
			proxySetting.IVCheck = false
		}

	case "dokodemo-door":
		protocol = "dokodemo-door"
		proxySetting = struct {
			Host        string   `json:"address"`
			NetworkList []string `json:"network"`
		}{
			Host:        "v1.mux.cool",
			NetworkList: []string{"tcp", "udp"},
		}
	case api.NodeTypeHY2:
		protocol = "hysteria"
		proxySetting = &conf.HysteriaServerConfig{Version: 2}
	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", nodeInfo.NodeType, err)
	}
	inboundDetourConfig.Protocol = protocol
	inboundDetourConfig.Settings = &setting

	// Build streamSettings
	streamSetting = new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol(nodeInfo.TransportProtocol)
	networkType, err := transportProtocol.Build()
	if err != nil {
		return nil, fmt.Errorf("convert TransportProtocol failed: %s", err)
	}

	switch networkType {
	case "tcp":
		tcpSetting := &conf.TCPConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol,
			HeaderConfig:        nodeInfo.Header,
		}
		streamSetting.TCPSettings = tcpSetting
	case "websocket":
		headers := make(map[string]string)
		headers["Host"] = nodeInfo.Host
		wsSettings := &conf.WebSocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol,
			Host:                nodeInfo.Host,
			Path:                nodeInfo.Path,
			Headers:             headers,
		}
		streamSetting.WSSettings = wsSettings
	case "splithttp":
		splitHTTPSettings := &conf.SplitHTTPConfig{
			Host:    nodeInfo.Host,
			Path:    nodeInfo.Path,
			Headers: nodeInfo.Headers,
		}
		streamSetting.SplitHTTPSettings = splitHTTPSettings
	case "grpc":
		grpcSettings := &conf.GRPCConfig{
			ServiceName: nodeInfo.ServiceName,
			Authority:   nodeInfo.Authority,
		}
		streamSetting.GRPCSettings = grpcSettings
	case "httpupgrade":
		httpupgradeSettings := &conf.HttpUpgradeConfig{
			Headers:             nodeInfo.Headers,
			Path:                nodeInfo.Path,
			Host:                nodeInfo.Host,
			AcceptProxyProtocol: nodeInfo.AcceptProxyProtocol,
		}
		streamSetting.HTTPUPGRADESettings = httpupgradeSettings
	case "hysteria":
		if nodeInfo.HysteriaConfig != nil {
			streamSetting.HysteriaSettings = nodeInfo.HysteriaConfig
		} else {
			streamSetting.HysteriaSettings = &conf.HysteriaConfig{Version: 2}
		}
	}
	streamSetting.Network = &transportProtocol

	// Build TLS and REALITY settings
	var isREALITY bool
	if config.DisableLocalREALITYConfig {
		if nodeInfo.REALITYConfig != nil && nodeInfo.EnableREALITY {
			isREALITY = true
			streamSetting.Security = "reality"

			r := nodeInfo.REALITYConfig
			streamSetting.REALITYSettings = &conf.REALITYConfig{
				Show:         config.REALITYConfigs.Show,
				Dest:         []byte(`"` + r.Dest + `"`),
				Xver:         r.ProxyProtocolVer,
				ServerNames:  r.ServerNames,
				PrivateKey:   r.PrivateKey,
				MinClientVer: r.MinClientVer,
				MaxClientVer: r.MaxClientVer,
				MaxTimeDiff:  r.MaxTimeDiff,
				ShortIds:     r.ShortIds,
			}
		}
	} else if config.EnableREALITY && config.REALITYConfigs != nil {
		isREALITY = true
		streamSetting.Security = "reality"

		streamSetting.REALITYSettings = &conf.REALITYConfig{
			Show:         config.REALITYConfigs.Show,
			Dest:         []byte(`"` + config.REALITYConfigs.Dest + `"`),
			Xver:         config.REALITYConfigs.ProxyProtocolVer,
			ServerNames:  config.REALITYConfigs.ServerNames,
			PrivateKey:   config.REALITYConfigs.PrivateKey,
			MinClientVer: config.REALITYConfigs.MinClientVer,
			MaxClientVer: config.REALITYConfigs.MaxClientVer,
			MaxTimeDiff:  config.REALITYConfigs.MaxTimeDiff,
			ShortIds:     config.REALITYConfigs.ShortIds,
		}
	}

	certConfig := config.CertConfig
	if certConfig == nil {
		certConfig = &CertConfig{CertMode: "none"}
	}
	certMode := normalizeCertMode(certConfig)

	if err := validateDirectVision(nodeInfo, networkType, isREALITY, certMode); err != nil {
		return nil, err
	}
	if networkType == "hysteria" && (!nodeInfo.EnableTLS || certMode == "none") {
		return nil, fmt.Errorf("hysteria2 requires TLS certificate config; got enable_tls=%v certmode=%s", nodeInfo.EnableTLS, certMode)
	}

	if !isREALITY && nodeInfo.EnableTLS && certMode != "none" {
		streamSetting.Security = "tls"
		certFile, keyFile, err := getCertFile(certConfig, nodeInfo)
		if err != nil {
			return nil, err
		}
		tlsSettings := &conf.TLSConfig{
			RejectUnknownSNI: certConfig.RejectUnknownSni,
		}
		if networkType == "hysteria" {
			tlsSettings.ALPN = &conf.StringList{"h3"}
			tlsSettings.MinVersion = "1.3"
			tlsSettings.MaxVersion = "1.3"
		}
		tlsSettings.Certs = append(tlsSettings.Certs, &conf.TLSCertConfig{CertFile: certFile, KeyFile: keyFile, OcspStapling: 3600})
		streamSetting.TLSSettings = tlsSettings
	}

	// Support ProxyProtocol for any transport protocol
	if networkType != "tcp" && networkType != "ws" && config.EnableProxyProtocol {
		sockoptConfig := &conf.SocketConfig{
			AcceptProxyProtocol: config.EnableProxyProtocol,
		}
		streamSetting.SocketSettings = sockoptConfig
	}
	inboundDetourConfig.StreamSetting = streamSetting

	return inboundDetourConfig.Build()
}

func getCertFile(certConfig *CertConfig, nodeInfo *api.NodeInfo) (certFile string, keyFile string, err error) {
	switch normalizeCertMode(certConfig) {
	case "file":
		if certConfig.CertFile == "" || certConfig.KeyFile == "" {
			return "", "", fmt.Errorf("cert file path or key file path not exist")
		}
		return certConfig.CertFile, certConfig.KeyFile, nil
	case "api":
		return getAPICertFile(certConfig, nodeInfo)
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", certConfig.CertMode)
	}
}

func normalizeCertMode(certConfig *CertConfig) string {
	if certConfig == nil {
		return "none"
	}
	mode := strings.ToLower(strings.TrimSpace(certConfig.CertMode))
	if mode == "" {
		return "none"
	}
	return mode
}

func validateDirectVision(nodeInfo *api.NodeInfo, networkType string, isREALITY bool, certMode string) error {
	if !isVLESSVision(nodeInfo) {
		return nil
	}
	if networkType != "tcp" {
		return fmt.Errorf("vless vision requires direct tcp transport, got %s", networkType)
	}
	if len(nodeInfo.Header) > 0 {
		return fmt.Errorf("vless vision requires direct tcp without tcp header")
	}
	if !isREALITY && (!nodeInfo.EnableTLS || certMode == "none") {
		return fmt.Errorf("vless vision requires TLS or REALITY; got enable_tls=%v certmode=%s", nodeInfo.EnableTLS, certMode)
	}
	return nil
}

func isVLESSVision(nodeInfo *api.NodeInfo) bool {
	if nodeInfo == nil {
		return false
	}
	return api.IsVlessNodeType(nodeInfo.NodeType, nodeInfo.EnableVless) &&
		strings.EqualFold(strings.TrimSpace(nodeInfo.VlessFlow), "xtls-rprx-vision")
}

type apiCertResponse struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

func getAPICertFile(certConfig *CertConfig, nodeInfo *api.NodeInfo) (certFile string, keyFile string, err error) {
	if nodeInfo.APIHost == "" || nodeInfo.APIKey == "" {
		return "", "", fmt.Errorf("api cert mode requires panel api host and key")
	}

	result := new(apiCertResponse)
	res, err := resty.New().
		SetTimeout(30*time.Second).
		R().
		SetHeader("User-Agent", "go-resty/2.7.0 (https://github.com/go-resty/resty)").
		SetQueryParams(map[string]string{
			"node_id":   strconv.Itoa(nodeInfo.NodeID),
			"node_type": api.CanonicalNodeType(nodeInfo.NodeType, nodeInfo.EnableVless),
			"token":     nodeInfo.APIKey,
		}).
		SetResult(result).
		ForceContentType("application/json").
		Get(strings.TrimRight(nodeInfo.APIHost, "/") + "/api/v1/server/UniProxy/cert")
	if err != nil {
		return "", "", fmt.Errorf("request api cert failed: %w", err)
	}
	if res.StatusCode() > 399 {
		return "", "", fmt.Errorf("request api cert failed: status %d", res.StatusCode())
	}
	if result.Cert == "" || result.Key == "" {
		return "", "", fmt.Errorf("api cert response missing cert or key")
	}

	certFile, keyFile = certConfig.CertFile, certConfig.KeyFile
	if certFile == "" || keyFile == "" {
		name := sanitizeAPICertName(result.Name)
		if name == "" {
			name = fmt.Sprintf("node-%d-%s", nodeInfo.NodeID, api.CanonicalNodeType(nodeInfo.NodeType, nodeInfo.EnableVless))
		}
		certFile = filepath.Join("cert", name+".cert")
		keyFile = filepath.Join("cert", name+".key")
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certFile, []byte(ensureTrailingNewline(result.Cert)), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyFile, []byte(ensureTrailingNewline(result.Key)), 0o600); err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}

func sanitizeAPICertName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, name)
}

func ensureTrailingNewline(value string) string {
	if strings.HasSuffix(value, "\n") {
		return value
	}
	return value + "\n"
}

func buildVlessFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.VLessInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	vlessFallBacks := make([]*conf.VLessInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		vlessFallBacks[i] = &conf.VLessInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return vlessFallBacks, nil
}

func buildTrojanFallbacks(fallbackConfigs []*FallBackConfig) ([]*conf.TrojanInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	trojanFallBacks := make([]*conf.TrojanInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback failed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config failed: %s", dest, err)
		}
		trojanFallBacks[i] = &conf.TrojanInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return trojanFallBacks, nil
}
