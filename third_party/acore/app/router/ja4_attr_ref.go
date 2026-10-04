package router

import (
	"encoding/base64"
	"strings"
)

const (
	internalJA4DBAttrPrefix   = "acore.internal.ja4db:"
	internalJA4DBAttrV2Prefix = "acore.internal.ja4db.v2:"
)

func EncodeJA4DBAttributeValue(file string, tag string) string {
	f := strings.TrimSpace(file)
	t := strings.ToLower(strings.TrimSpace(tag))
	return internalJA4DBAttrV2Prefix +
		base64.RawURLEncoding.EncodeToString([]byte(f)) + ":" +
		base64.RawURLEncoding.EncodeToString([]byte(t))
}

func decodeLegacyJA4DBAttributeValue(value string) (file string, tag string, ok bool) {
	rest := value[len(internalJA4DBAttrPrefix):]
	sep := strings.LastIndex(rest, ":")
	if sep <= 0 || sep+1 >= len(rest) {
		return "", "", false
	}
	file = strings.TrimSpace(rest[:sep])
	tag = strings.ToLower(strings.TrimSpace(rest[sep+1:]))
	if file == "" || tag == "" {
		return "", "", false
	}
	return file, tag, true
}

func decodeV2JA4DBAttributeValue(value string) (file string, tag string, ok bool) {
	rest := value[len(internalJA4DBAttrV2Prefix):]
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	encFile := strings.TrimSpace(parts[0])
	encTag := strings.TrimSpace(parts[1])
	if encFile == "" || encTag == "" {
		return "", "", false
	}
	fileBytes, err := base64.RawURLEncoding.DecodeString(encFile)
	if err != nil {
		return "", "", false
	}
	tagBytes, err := base64.RawURLEncoding.DecodeString(encTag)
	if err != nil {
		return "", "", false
	}
	file = strings.TrimSpace(string(fileBytes))
	tag = strings.ToLower(strings.TrimSpace(string(tagBytes)))
	if file == "" || tag == "" {
		return "", "", false
	}
	return file, tag, true
}

func DecodeJA4DBAttributeValue(value string) (file string, tag string, ok bool) {
	s := strings.TrimSpace(value)
	if s == "" {
		return "", "", false
	}
	ls := strings.ToLower(s)
	switch {
	case strings.HasPrefix(ls, internalJA4DBAttrV2Prefix):
		return decodeV2JA4DBAttributeValue(s)
	case strings.HasPrefix(ls, internalJA4DBAttrPrefix):
		return decodeLegacyJA4DBAttributeValue(s)
	default:
		return "", "", false
	}
}
