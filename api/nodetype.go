package api

import "strings"

const (
	NodeTypeHY2 = "hy2"
)

func CanonicalNodeType(nodeType string, enableVless bool) string {
	normalized := strings.ToLower(strings.TrimSpace(nodeType))
	if normalized == "v2ray" && enableVless {
		return "vless"
	}
	if IsHysteriaNodeType(normalized) {
		return NodeTypeHY2
	}
	return normalized
}

func IsHysteriaNodeType(nodeType string) bool {
	switch strings.ToLower(strings.TrimSpace(nodeType)) {
	case NodeTypeHY2, "hysteria", "hysteria2":
		return true
	default:
		return false
	}
}

func IsVlessNodeType(nodeType string, enableVless bool) bool {
	return enableVless || strings.EqualFold(strings.TrimSpace(nodeType), "vless")
}
