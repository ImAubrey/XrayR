package conf

import (
	"strings"

	"github.com/ImAubrey/acore/app/commander"
	conntrackservice "github.com/ImAubrey/acore/app/conntrack/command"
	loggerservice "github.com/ImAubrey/acore/app/log/command"
	metricsservice "github.com/ImAubrey/acore/app/metrics"
	observatoryservice "github.com/ImAubrey/acore/app/observatory/command"
	handlerservice "github.com/ImAubrey/acore/app/proxyman/command"
	routerservice "github.com/ImAubrey/acore/app/router/command"
	startupservice "github.com/ImAubrey/acore/app/startup/command"
	statsservice "github.com/ImAubrey/acore/app/stats/command"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/serial"
)

type APIConfig struct {
	Tag      string   `json:"tag"`
	Listen   string   `json:"listen"`
	Services []string `json:"services"`
}

func (c *APIConfig) Build() (*commander.Config, error) {
	if c.Tag == "" {
		return nil, errors.New("API tag can't be empty.")
	}

	services := make([]*serial.TypedMessage, 0, 16)
	for _, s := range c.Services {
		switch strings.ToLower(s) {
		case "reflectionservice":
			services = append(services, serial.ToTypedMessage(&commander.ReflectionConfig{}))
		case "connectionservice", "connectionsservice":
			services = append(services, serial.ToTypedMessage(&conntrackservice.Config{}))
		case "handlerservice":
			services = append(services, serial.ToTypedMessage(&handlerservice.Config{}))
		case "loggerservice":
			services = append(services, serial.ToTypedMessage(&loggerservice.Config{}))
		case "statsservice":
			services = append(services, serial.ToTypedMessage(&statsservice.Config{}))
		case "observatoryservice":
			services = append(services, serial.ToTypedMessage(&observatoryservice.Config{}))
		case "metricsservice", "metricsgrpcservice":
			services = append(services, serial.ToTypedMessage(&metricsservice.GrpcConfig{}))
		case "routingservice":
			services = append(services, serial.ToTypedMessage(&routerservice.Config{}))
		case "startupservice":
			services = append(services, serial.ToTypedMessage(&startupservice.Config{}))
		}
	}

	return &commander.Config{
		Tag:     c.Tag,
		Listen:  c.Listen,
		Service: services,
	}, nil
}
