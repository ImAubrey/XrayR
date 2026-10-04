package conf

import (
	"encoding/json"
	"strings"

	"github.com/ImAubrey/acore/common/errors"
)

// ManagedOutboundConfig supports both legacy string and object forms:
// - "managed": "sub-name"
// - "managed": { "subscription": "sub-name", "rewrite": { ... } }
type ManagedOutboundConfig struct {
	Subscription string         `json:"subscription,omitempty"`
	Rewrite      map[string]any `json:"rewrite,omitempty"`
}

func (m *ManagedOutboundConfig) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("nil managed config")
	}
	*m = ManagedOutboundConfig{}
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var subName string
	if err := json.Unmarshal(data, &subName); err == nil {
		m.Subscription = strings.TrimSpace(subName)
		return nil
	}
	type alias ManagedOutboundConfig
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return errors.New("invalid outbound managed config")
	}
	m.Subscription = strings.TrimSpace(v.Subscription)
	m.Rewrite = sanitizeManagedRewrite(v.Rewrite)
	return nil
}

func (m ManagedOutboundConfig) MarshalJSON() ([]byte, error) {
	subName := strings.TrimSpace(m.Subscription)
	rewrite := sanitizeManagedRewrite(m.Rewrite)
	obj := map[string]any{}
	if subName != "" {
		obj["subscription"] = subName
	}
	if len(rewrite) > 0 {
		obj["rewrite"] = rewrite
	}
	if len(obj) == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(obj)
}

func managedSubscriptionName(m *ManagedOutboundConfig) string {
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m.Subscription)
}

func managedRewritePatch(m *ManagedOutboundConfig) map[string]any {
	if m == nil {
		return nil
	}
	return sanitizeManagedRewrite(m.Rewrite)
}

func sanitizeManagedRewrite(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		if strings.EqualFold(key, "tag") {
			continue
		}
		if v == nil {
			continue
		}
		switch typed := v.(type) {
		case map[string]any:
			nested := sanitizeManagedRewrite(typed)
			if len(nested) == 0 {
				continue
			}
			out[key] = nested
		default:
			out[key] = typed
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneManagedRewrite(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch typed := v.(type) {
		case map[string]any:
			out[k] = cloneManagedRewrite(typed)
		default:
			out[k] = typed
		}
	}
	return out
}
