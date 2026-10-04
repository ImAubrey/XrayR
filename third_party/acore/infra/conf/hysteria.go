package conf

import (
	"strings"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/proxy/hysteria"
	"github.com/ImAubrey/acore/proxy/hysteria/account"
	hytransport "github.com/ImAubrey/acore/transport/internet/hysteria"
	"google.golang.org/protobuf/proto"
)

type HysteriaClientConfig struct {
	Version int32    `json:"version"`
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
}

func (c *HysteriaClientConfig) Build() (proto.Message, error) {
	if c.Version != 2 {
		return nil, errors.New("version != 2")
	}
	if c.Address == nil {
		return nil, errors.New("address is required")
	}

	return &hysteria.ClientConfig{
		Version: c.Version,
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
		},
	}, nil
}

type HysteriaUserConfig struct {
	Auth  string `json:"auth"`
	Level uint32 `json:"level"`
	Email string `json:"email"`
}

type HysteriaServerConfig struct {
	Version int32                 `json:"version"`
	Users   []*HysteriaUserConfig `json:"clients"`
}

func (c *HysteriaServerConfig) Build() (proto.Message, error) {
	config := new(hysteria.ServerConfig)

	for _, user := range c.Users {
		config.Users = append(config.Users, &protocol.User{
			Email: user.Email,
			Level: user.Level,
			Account: serial.ToTypedMessage(&account.Account{
				Auth: user.Auth,
			}),
		})
	}

	return config, nil
}

type HysteriaMasqueradeConfig struct {
	Type        string            `json:"type"`
	Dir         string            `json:"dir"`
	URL         string            `json:"url"`
	RewriteHost bool              `json:"rewriteHost"`
	Insecure    bool              `json:"insecure"`
	Content     string            `json:"content"`
	Headers     map[string]string `json:"headers"`
	StatusCode  int32             `json:"statusCode"`
}

type HysteriaConfig struct {
	Version        int32                    `json:"version"`
	Auth           string                   `json:"auth"`
	UDPIdleTimeout int64                    `json:"udpIdleTimeout"`
	Obfs           string                   `json:"obfs"`
	ObfsPassword   string                   `json:"obfsPassword"`
	Masquerade     HysteriaMasqueradeConfig `json:"masquerade"`
}

func (c *HysteriaConfig) Build() (proto.Message, error) {
	if c.Version != 2 {
		return nil, errors.New("version != 2")
	}
	if c.UDPIdleTimeout != 0 && (c.UDPIdleTimeout < 2 || c.UDPIdleTimeout > 600) {
		return nil, errors.New("udpIdleTimeout must be between 2 and 600")
	}

	config := &hytransport.Config{
		Version:              c.Version,
		Auth:                 c.Auth,
		UdpIdleTimeout:       c.UDPIdleTimeout,
		MasqType:             c.Masquerade.Type,
		MasqFile:             c.Masquerade.Dir,
		MasqUrl:              c.Masquerade.URL,
		MasqUrlRewriteHost:   c.Masquerade.RewriteHost,
		MasqUrlInsecure:      c.Masquerade.Insecure,
		MasqString:           c.Masquerade.Content,
		MasqStringHeaders:    c.Masquerade.Headers,
		MasqStringStatusCode: c.Masquerade.StatusCode,
	}
	if config.UdpIdleTimeout == 0 {
		config.UdpIdleTimeout = 60
	}

	if c.Obfs != "" {
		if strings.ToLower(c.Obfs) != "salamander" {
			return nil, errors.New("unsupported hysteria obfs: ", c.Obfs)
		}
		if config.MasqStringHeaders == nil {
			config.MasqStringHeaders = make(map[string]string)
		}
		config.MasqStringHeaders["x-acore-hysteria-obfs"] = c.Obfs
		config.MasqStringHeaders["x-acore-hysteria-obfs-password"] = c.ObfsPassword
	}

	return config, nil
}
