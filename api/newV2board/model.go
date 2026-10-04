package newV2board

import (
	"encoding/json"
	"strconv"
	"strings"
)

type flexibleInt int

func (v *flexibleInt) UnmarshalJSON(data []byte) error {
	value, err := parseFlexibleInt(data, nil)
	if err != nil {
		return err
	}
	*v = flexibleInt(value)
	return nil
}

type flexibleUint64 uint64

func (v *flexibleUint64) UnmarshalJSON(data []byte) error {
	value, err := parseFlexibleInt(data, nil)
	if err != nil {
		return err
	}
	if value < 0 {
		value = 0
	}
	*v = flexibleUint64(value)
	return nil
}

type flexibleString string

func (v *flexibleString) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		*v = ""
		return nil
	}
	if strings.HasPrefix(raw, `"`) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*v = flexibleString(s)
		return nil
	}
	*v = flexibleString(raw)
	return nil
}

func (v flexibleString) String() string {
	return string(v)
}

type tlsMode int

func (v *tlsMode) UnmarshalJSON(data []byte) error {
	value, err := parseFlexibleInt(data, map[string]int{
		"none":    0,
		"false":   0,
		"off":     0,
		"tls":     1,
		"true":    1,
		"on":      1,
		"reality": 2,
	})
	if err != nil {
		return err
	}
	*v = tlsMode(value)
	return nil
}

type flexibleBool bool

func (v *flexibleBool) UnmarshalJSON(data []byte) error {
	value, err := parseFlexibleInt(data, map[string]int{
		"false": 0,
		"off":   0,
		"no":    0,
		"true":  1,
		"on":    1,
		"yes":   1,
	})
	if err != nil {
		return err
	}
	*v = value != 0
	return nil
}

func parseFlexibleInt(data []byte, aliases map[string]int) (int, error) {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" {
		return 0, nil
	}
	if strings.HasPrefix(raw, `"`) {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return 0, err
		}
		raw = strings.TrimSpace(s)
	}
	lower := strings.ToLower(raw)
	if aliases != nil {
		if value, ok := aliases[lower]; ok {
			return value, nil
		}
	}
	switch lower {
	case "", "null", "false":
		return 0, nil
	case "true":
		return 1, nil
	}
	if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return int(i), nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, err
	}
	return int(f), nil
}

type serverConfig struct {
	shadowsocks
	v2ray
	trojan

	ServerPort flexibleInt `json:"server_port"`
	Version    flexibleInt `json:"version"`
	UpMbps     flexibleInt `json:"up_mbps"`
	DownMbps   flexibleInt `json:"down_mbps"`
	BaseConfig struct {
		PushInterval flexibleInt `json:"push_interval"`
		PullInterval flexibleInt `json:"pull_interval"`
	} `json:"base_config"`
	Routes                []route      `json:"routes"`
	Insecure              flexibleBool `json:"insecure"`
	IgnoreClientBandwidth flexibleBool `json:"ignore_client_bandwidth"`
	ObfsPassword          string       `json:"obfs_password"`
}

type shadowsocks struct {
	Cipher       string `json:"cipher"`
	Obfs         string `json:"obfs"`
	ObfsSettings struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"obfs_settings"`
	ServerKey string `json:"server_key"`
}

type v2ray struct {
	Network         string `json:"network"`
	NetworkSettings struct {
		Path        string           `json:"path"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
		Header      *json.RawMessage `json:"header"`
	} `json:"networkSettings"`
	VlessNetworkSettings struct {
		Path        string           `json:"path"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
		Header      *json.RawMessage `json:"header"`
	} `json:"network_settings"`
	VlessFlow        string `json:"flow"`
	VlessTlsSettings struct {
		ServerPort flexibleString `json:"server_port"`
		Dest       string         `json:"dest"`
		Xver       flexibleUint64 `json:"xver"`
		Sni        string         `json:"server_name"`
		PrivateKey string         `json:"private_key"`
		ShortId    string         `json:"short_id"`
	} `json:"tls_settings"`
	Tls tlsMode `json:"tls"`
}

type trojan struct {
	Host       string `json:"host"`
	ServerName string `json:"server_name"`
}

type route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value"`
}

type user struct {
	Id         flexibleInt `json:"id"`
	Uuid       string      `json:"uuid"`
	Password   string      `json:"password"`
	Passwd     string      `json:"passwd"`
	SpeedLimit flexibleInt `json:"speed_limit"`
}
