package internet

import (
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/serial"
)

type ConfigCreator func() interface{}

var (
	globalTransportConfigCreatorCache = make(map[string]ConfigCreator)
)

// strategyInfo 描述域名解析策略的属性
type strategyInfo struct {
	resolve  bool // 是否需要解析域名
	strict   bool // 解析失败时是否断开连接（false=透传域名）
	onlyIPv4 bool // 仅使用 IPv4
	onlyIPv6 bool // 仅使用 IPv6
	prefer4  bool // 优先 IPv4（有回退）
	prefer6  bool // 优先 IPv6（有回退）
}

// strategyTable 映射 DomainStrategy 枚举值到属性
var strategyTable = []strategyInfo{
	// AS_IS: 不解析
	{resolve: false},
	// USE_IP: 解析（双栈），失败透传
	{resolve: true, strict: false},
	// USE_IP4: 仅 IPv4，失败透传
	{resolve: true, strict: false, onlyIPv4: true},
	// USE_IP6: 仅 IPv6，失败透传
	{resolve: true, strict: false, onlyIPv6: true},
	// USE_IP46: 优先 IPv4 回退 IPv6，失败透传
	{resolve: true, strict: false, prefer4: true},
	// USE_IP64: 优先 IPv6 回退 IPv4，失败透传
	{resolve: true, strict: false, prefer6: true},
	// FORCE_IP: 解析（双栈），失败断开
	{resolve: true, strict: true},
	// FORCE_IP4: 仅 IPv4，失败断开
	{resolve: true, strict: true, onlyIPv4: true},
	// FORCE_IP6: 仅 IPv6，失败断开
	{resolve: true, strict: true, onlyIPv6: true},
	// FORCE_IP46: 优先 IPv4 回退 IPv6，失败断开
	{resolve: true, strict: true, prefer4: true},
	// FORCE_IP64: 优先 IPv6 回退 IPv4，失败断开
	{resolve: true, strict: true, prefer6: true},
}

const unknownProtocol = "unknown"

func RegisterProtocolConfigCreator(name string, creator ConfigCreator) error {
	if _, found := globalTransportConfigCreatorCache[name]; found {
		return errors.New("protocol ", name, " is already registered").AtError()
	}
	globalTransportConfigCreatorCache[name] = creator
	return nil
}

// Note: Each new transport needs to add init() func in transport/internet/xxx/config.go
// Otherwise, it will cause #3244
func CreateTransportConfig(name string) (interface{}, error) {
	creator, ok := globalTransportConfigCreatorCache[name]
	if !ok {
		return nil, errors.New("unknown transport protocol: ", name)
	}
	return creator(), nil
}

func (c *TransportConfig) GetTypedSettings() (interface{}, error) {
	return c.Settings.GetInstance()
}

func (c *TransportConfig) GetUnifiedProtocolName() string {
	return c.ProtocolName
}

func (c *StreamConfig) GetEffectiveProtocol() string {
	if c == nil || len(c.ProtocolName) == 0 {
		return "tcp"
	}

	return c.ProtocolName
}

func (c *StreamConfig) GetEffectiveTransportSettings() (interface{}, error) {
	protocol := c.GetEffectiveProtocol()
	return c.GetTransportSettingsFor(protocol)
}

func (c *StreamConfig) GetTransportSettingsFor(protocol string) (interface{}, error) {
	if c != nil {
		for _, settings := range c.TransportSettings {
			if settings.GetUnifiedProtocolName() == protocol {
				return settings.GetTypedSettings()
			}
		}
	}

	return CreateTransportConfig(protocol)
}

func (c *StreamConfig) GetEffectiveSecuritySettings() (interface{}, error) {
	for _, settings := range c.SecuritySettings {
		if settings.Type == c.SecurityType {
			return settings.GetInstance()
		}
	}
	return serial.GetInstance(c.SecurityType)
}

func (c *StreamConfig) HasSecuritySettings() bool {
	return len(c.SecurityType) > 0
}

func (m SocketConfig_TProxyMode) IsEnabled() bool {
	return m != SocketConfig_Off
}

// info 返回策略的属性信息
func (s DomainStrategy) info() strategyInfo {
	if int(s) < len(strategyTable) {
		return strategyTable[s]
	}
	return strategyInfo{}
}

// ShouldResolve 返回是否需要解析域名
func (s DomainStrategy) ShouldResolve() bool {
	return s.info().resolve
}

// IsStrict 返回解析失败时是否断开连接（严格模式）
func (s DomainStrategy) IsStrict() bool {
	return s.info().strict
}

// OnlyIPv4 返回是否仅使用 IPv4
func (s DomainStrategy) OnlyIPv4() bool {
	return s.info().onlyIPv4
}

// OnlyIPv6 返回是否仅使用 IPv6
func (s DomainStrategy) OnlyIPv6() bool {
	return s.info().onlyIPv6
}

// HasFallback 返回是否有回退选项
func (s DomainStrategy) HasFallback() bool {
	info := s.info()
	return info.prefer4 || info.prefer6
}

// PreferIP4 返回是否优先或仅使用 IPv4
func (s DomainStrategy) PreferIP4() bool {
	info := s.info()
	return info.onlyIPv4 || info.prefer4
}

// PreferIP6 返回是否优先或仅使用 IPv6
func (s DomainStrategy) PreferIP6() bool {
	info := s.info()
	return info.onlyIPv6 || info.prefer6
}

// FallbackIP4 返回回退是否为 IPv4
func (s DomainStrategy) FallbackIP4() bool {
	return s.info().prefer6 // 优先 IPv6 时回退到 IPv4
}

// FallbackIP6 返回回退是否为 IPv6
func (s DomainStrategy) FallbackIP6() bool {
	return s.info().prefer4 // 优先 IPv4 时回退到 IPv6
}

// HasStrategy 返回是否有策略（向后兼容别名）
func (s DomainStrategy) HasStrategy() bool {
	return s.ShouldResolve()
}

// ForceIP 返回是否为强制模式（向后兼容别名）
func (s DomainStrategy) ForceIP() bool {
	return s.IsStrict()
}

// GetDynamicStrategy 根据地址族动态调整策略
func (s DomainStrategy) GetDynamicStrategy(addrFamily net.AddressFamily) DomainStrategy {
	if addrFamily.IsDomain() {
		return s
	}
	switch s {
	case DomainStrategy_USE_IP:
		if addrFamily.IsIPv4() {
			return DomainStrategy_USE_IP46
		} else if addrFamily.IsIPv6() {
			return DomainStrategy_USE_IP64
		}
	case DomainStrategy_FORCE_IP:
		if addrFamily.IsIPv4() {
			return DomainStrategy_FORCE_IP46
		} else if addrFamily.IsIPv6() {
			return DomainStrategy_FORCE_IP64
		}
	}
	return s
}
