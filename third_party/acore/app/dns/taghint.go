package dns

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

const dnsTagPrefix = "acore-dns-tag:"

type dnsTagPayload struct {
	Tag          string   `json:"tag"`
	OutboundTags []string `json:"outboundTags,omitempty"`
}

func decodeDNSTag(tag string, defaultTag string) (string, []string) {
	if !strings.HasPrefix(tag, dnsTagPrefix) {
		return tag, nil
	}
	raw := strings.TrimPrefix(tag, dnsTagPrefix)
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return tag, nil
	}
	var payload dnsTagPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return tag, nil
	}
	inboundTag := payload.Tag
	if inboundTag == "" {
		inboundTag = defaultTag
	}
	return inboundTag, payload.OutboundTags
}
