package router

import (
	"strings"
)

func normalizeJA4MatchedTag(_ string, tag string) string {
	normalizedTag := strings.ToLower(strings.TrimSpace(tag))
	if normalizedTag == "" {
		return ""
	}
	return normalizedTag
}
