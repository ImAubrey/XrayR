package conf

import (
	"encoding/json"
	"strings"

	"github.com/ImAubrey/acore/common/errors"
)

type SendThroughArrayItem struct {
	Tag string  `json:"tag"`
	V4  *string `json:"v4"`
	V6  *string `json:"v6"`
}

// SendThroughConfig accepts either the legacy string form or an array of
// outbound templates that will be expanded during config post-processing.
type SendThroughConfig struct {
	Raw      *string                `json:"-"`
	Array    []SendThroughArrayItem `json:"-"`
	ArraySet bool                   `json:"-"`
}

func (c *SendThroughConfig) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*c = SendThroughConfig{}
		return nil
	}

	var raw string
	if err := json.Unmarshal(data, &raw); err == nil {
		*c = SendThroughConfig{Raw: &raw}
		return nil
	}

	var array []SendThroughArrayItem
	if err := json.Unmarshal(data, &array); err == nil {
		*c = SendThroughConfig{Array: array, ArraySet: true}
		return nil
	}

	return errors.New("invalid sendThrough: expected string or array of objects")
}

func (c SendThroughConfig) MarshalJSON() ([]byte, error) {
	switch {
	case c.ArraySet:
		if c.Array == nil {
			return json.Marshal([]SendThroughArrayItem{})
		}
		return json.Marshal(c.Array)
	case c.Raw != nil:
		return json.Marshal(*c.Raw)
	default:
		return json.Marshal(nil)
	}
}

func (c SendThroughConfig) Scalar() *string {
	return c.Raw
}

func (c SendThroughConfig) IsArray() bool {
	return c.ArraySet
}

func expandOutboundSendThroughTemplates(conf *Config) error {
	if conf == nil || len(conf.OutboundConfigs) == 0 {
		return nil
	}

	expanded := make([]OutboundDetourConfig, 0, len(conf.OutboundConfigs))
	for i, outbound := range conf.OutboundConfigs {
		group, err := outbound.expandSendThrough(i)
		if err != nil {
			return err
		}
		expanded = append(expanded, group...)
	}

	conf.OutboundConfigs = expanded
	return nil
}

func (outbound OutboundDetourConfig) expandSendThrough(index int) ([]OutboundDetourConfig, error) {
	if !outbound.SendThrough.IsArray() {
		return []OutboundDetourConfig{outbound}, nil
	}
	if err := outbound.validateSendThroughArray(index); err != nil {
		return nil, err
	}
	group := make([]OutboundDetourConfig, 0, len(outbound.SendThrough.Array)+1)
	parentTag := strings.TrimSpace(outbound.Tag)
	for itemIndex, item := range outbound.SendThrough.Array {
		expanded, err := outbound.withSendThroughItem(index, itemIndex, item)
		if err != nil {
			return nil, err
		}
		if itemIndex == 0 && parentTag != "" && parentTag != expanded.Tag {
			// Preserve the parent tag as an alias to the first expanded outbound.
			alias := expanded
			alias.Tag = parentTag
			group = append(group, alias)
		}
		group = append(group, expanded)
	}
	return group, nil
}

func (outbound OutboundDetourConfig) validateSendThroughArray(index int) error {
	if outbound.SendThrough6 != nil {
		return errors.New("outbounds[", index, "]: sendThrough6 cannot be used when sendThrough is array; use v6 in each item")
	}
	if len(outbound.SendThrough.Array) == 0 {
		return errors.New("outbounds[", index, "]: sendThrough array must not be empty")
	}
	return nil
}

func (outbound OutboundDetourConfig) withSendThroughItem(outboundIndex int, itemIndex int, item SendThroughArrayItem) (OutboundDetourConfig, error) {
	tag := strings.TrimSpace(item.Tag)
	if tag == "" {
		return OutboundDetourConfig{}, errors.New("outbounds[", outboundIndex, "].sendThrough[", itemIndex, "]: tag is required")
	}
	if item.V6 != nil && item.V4 == nil {
		return OutboundDetourConfig{}, errors.New("outbounds[", outboundIndex, "].sendThrough[", itemIndex, "]: v6 requires v4")
	}
	clone := outbound
	clone.Tag = tag
	clone.SendThrough = SendThroughConfig{Raw: cloneStringPtr(item.V4)}
	clone.SendThrough6 = cloneStringPtr(item.V6)
	return clone, nil
}

func cloneStringPtr(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
