package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	json_reader "github.com/ImAubrey/acore/infra/conf/json"
	"github.com/ghodss/yaml"
)

type ParseResult struct {
	Outbounds []json.RawMessage
	Warnings  []string
}

func normalizeFormat(raw string) string {
	v := strings.TrimSpace(strings.ToLower(raw))
	switch v {
	case "":
		return "auto"
	case "yml":
		return "yaml"
	case "acore", "share", "sharelink", "sharelinks", "base64", "b64":
		return "share"
	default:
		return v
	}
}

func inferFormatFromURL(urlHint string) string {
	hint := strings.TrimSpace(urlHint)
	if hint == "" {
		return "json"
	}
	// Try to infer from URL path first.
	if u, err := url.Parse(hint); err == nil && u != nil && u.Path != "" {
		switch strings.ToLower(filepath.Ext(u.Path)) {
		case ".yaml", ".yml":
			return "yaml"
		case ".json", ".jsonc":
			return "json"
		}
	}
	switch strings.ToLower(filepath.Ext(hint)) {
	case ".yaml", ".yml":
		return "yaml"
	case ".json", ".jsonc":
		return "json"
	default:
		return "json"
	}
}

func ParseOutboundSubscription(body []byte, format string, urlHint string) (ParseResult, error) {
	f := normalizeFormat(format)
	switch f {
	case "auto":
		guessed := inferFormatFromURL(urlHint)
		if guessed == "yaml" {
			if res, err := parseYAMLOutbounds(body); err == nil {
				return res, nil
			}
		}
		if res, err := parseJSONOutbounds(body); err == nil {
			return res, nil
		}
		// Auto fallback: standard share subscription.
		return parseShareOutbounds(body)
	case "json", "jsonc":
		return parseJSONOutbounds(body)
	case "yaml":
		return parseYAMLOutbounds(body)
	case "share":
		return parseShareOutbounds(body)
	default:
		return ParseResult{}, stderrors.New("unsupported subscription format: " + f)
	}
}

func parseJSONOutbounds(body []byte) (ParseResult, error) {
	decoder := json.NewDecoder(&json_reader.Reader{Reader: bytes.NewReader(body)})
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return ParseResult{}, err
	}
	outboundsAny, ok := extractOutboundsAny(root)
	if !ok {
		return ParseResult{}, stderrors.New("no outbounds found in json")
	}
	outbounds := make([]json.RawMessage, 0, len(outboundsAny))
	for _, ob := range outboundsAny {
		b, err := json.Marshal(ob)
		if err != nil {
			return ParseResult{}, err
		}
		outbounds = append(outbounds, b)
	}
	return ParseResult{Outbounds: outbounds}, nil
}

func parseYAMLOutbounds(body []byte) (ParseResult, error) {
	jsonBody, err := yaml.YAMLToJSON(body)
	if err != nil {
		return ParseResult{}, err
	}
	// YAML doesn't support comments like jsonc; after conversion it's plain json.
	return parseJSONOutbounds(jsonBody)
}

func extractOutboundsAny(root any) ([]any, bool) {
	switch v := root.(type) {
	case []any:
		return v, true
	case map[string]any:
		raw, ok := v["outbounds"]
		if !ok {
			return nil, false
		}
		list, ok := raw.([]any)
		if !ok {
			return nil, false
		}
		return list, true
	default:
		return nil, false
	}
}

func stripAllWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func tryDecodeBase64String(s string) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	trimmed := stripAllWhitespace(s)
	// Try several common encodings (raw and padded, std and url).
	encodings := []*base64.Encoding{
		base64.RawStdEncoding,
		base64.StdEncoding,
		base64.RawURLEncoding,
		base64.URLEncoding,
	}
	for _, enc := range encodings {
		if b, err := enc.DecodeString(trimmed); err == nil && len(b) > 0 {
			return b, true
		}
	}
	return nil, false
}

func looksLikeJSON(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}

func looksLikeYAML(s string) bool {
	t := strings.TrimSpace(s)
	// Minimal heuristic: common wrapper.
	return strings.HasPrefix(t, "outbounds:") || strings.Contains(t, "\noutbounds:")
}

func parseShareOutbounds(body []byte) (ParseResult, error) {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return ParseResult{}, stderrors.New("empty subscription body")
	}

	// Standard subscription is usually Base64(text). If it's Base64(JSON/YAML), decode and parse as such.
	if decoded, ok := tryDecodeBase64String(raw); ok {
		decodedText := strings.TrimSpace(string(decoded))
		if decodedText != "" {
			if looksLikeJSON(decodedText) {
				if res, err := parseJSONOutbounds([]byte(decodedText)); err == nil {
					return res, nil
				}
			}
			if looksLikeYAML(decodedText) {
				if res, err := parseYAMLOutbounds([]byte(decodedText)); err == nil {
					return res, nil
				}
			}
			raw = decodedText
		}
	}

	lines := splitNonEmptyLines(raw)
	var res ParseResult
	for _, line := range lines {
		ob, warns, err := parseShareLinkToOutbound(line)
		for _, w := range warns {
			if w != "" {
				res.Warnings = append(res.Warnings, w)
			}
		}
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
			continue
		}
		if ob == nil {
			continue
		}
		b, err := json.Marshal(ob)
		if err != nil {
			return ParseResult{}, err
		}
		res.Outbounds = append(res.Outbounds, b)
	}
	if len(res.Outbounds) == 0 {
		return ParseResult{}, stderrors.New("no supported share links found in subscription")
	}
	return res, nil
}

func splitNonEmptyLines(text string) []string {
	raw := strings.ReplaceAll(text, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		line := strings.TrimSpace(p)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func parseShareLinkToOutbound(raw string) (map[string]any, []string, error) {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return parseVLessLink(raw)
	case strings.HasPrefix(lower, "vmess://"):
		return parseVMessLink(raw)
	case strings.HasPrefix(lower, "trojan://"):
		return parseTrojanLink(raw)
	case strings.HasPrefix(lower, "ss://"):
		return parseShadowsocksLink(raw)
	default:
		return nil, nil, stderrors.New("unsupported share link: " + raw)
	}
}

func decodeFragment(fragment string) string {
	if fragment == "" {
		return ""
	}
	if decoded, err := url.PathUnescape(fragment); err == nil {
		return strings.TrimSpace(decoded)
	}
	return strings.TrimSpace(fragment)
}

func getFirstQuery(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func parseNetworkType(q url.Values) string {
	return strings.TrimSpace(strings.ToLower(getFirstQuery(q, "type", "network", "net")))
}

func parseSecurity(q url.Values) string {
	return strings.TrimSpace(strings.ToLower(getFirstQuery(q, "security", "tls")))
}

func parseALPN(raw string) []string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if x := strings.TrimSpace(p); x != "" {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseHostPort(hostport string, defaultPort int) (host string, port int, err error) {
	if hostport == "" {
		return "", 0, stderrors.New("missing host")
	}
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		// Some share links may omit port.
		if defaultPort > 0 && strings.Contains(err.Error(), "missing port in address") {
			return hostport, defaultPort, nil
		}
		return "", 0, err
	}
	portNum, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, err
	}
	return h, portNum, nil
}

func buildStreamSettings(q url.Values) map[string]any {
	network := parseNetworkType(q)
	security := parseSecurity(q)
	sni := getFirstQuery(q, "sni", "serverName", "servername")
	alpn := parseALPN(getFirstQuery(q, "alpn"))
	fp := strings.TrimSpace(getFirstQuery(q, "fp", "fingerprint"))

	stream := map[string]any{}
	if network != "" {
		stream["network"] = network
	}
	switch security {
	case "", "none":
	case "tls":
		stream["security"] = "tls"
		tlsSettings := map[string]any{}
		if sni != "" {
			tlsSettings["serverName"] = sni
		}
		if len(alpn) > 0 {
			tlsSettings["alpn"] = alpn
		}
		if fp != "" {
			tlsSettings["fingerprint"] = fp
		}
		if len(tlsSettings) > 0 {
			stream["tlsSettings"] = tlsSettings
		}
	case "reality":
		stream["security"] = "reality"
		realitySettings := map[string]any{}
		if sni != "" {
			realitySettings["serverName"] = sni
		}
		if fp != "" {
			realitySettings["fingerprint"] = fp
		}
		if pbk := strings.TrimSpace(getFirstQuery(q, "pbk", "publicKey", "publickey")); pbk != "" {
			realitySettings["publicKey"] = pbk
		}
		if sid := strings.TrimSpace(getFirstQuery(q, "sid", "shortId", "shortid")); sid != "" {
			realitySettings["shortId"] = sid
		}
		if spx := strings.TrimSpace(getFirstQuery(q, "spx", "spiderX", "spiderx")); spx != "" {
			realitySettings["spiderX"] = spx
		}
		if len(realitySettings) > 0 {
			stream["realitySettings"] = realitySettings
		}
	default:
		// Unknown security: keep it as-is.
		stream["security"] = security
	}

	switch network {
	case "ws", "websocket":
		wsSettings := map[string]any{}
		if h := strings.TrimSpace(getFirstQuery(q, "host")); h != "" {
			wsSettings["host"] = h
		}
		if p := strings.TrimSpace(getFirstQuery(q, "path")); p != "" {
			wsSettings["path"] = p
		}
		if len(wsSettings) > 0 {
			stream["wsSettings"] = wsSettings
		}
	case "grpc":
		grpcSettings := map[string]any{}
		if sn := strings.TrimSpace(getFirstQuery(q, "serviceName", "servicename")); sn != "" {
			grpcSettings["serviceName"] = sn
		}
		if len(grpcSettings) > 0 {
			stream["grpcSettings"] = grpcSettings
		}
	}

	if len(stream) == 0 {
		return nil
	}
	return stream
}

func parseVLessLink(raw string) (map[string]any, []string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	id := ""
	if u.User != nil {
		id = strings.TrimSpace(u.User.Username())
	}
	host, port, err := parseHostPort(u.Host, 0)
	if err != nil {
		return nil, nil, err
	}
	q := u.Query()

	settings := map[string]any{
		"address": host,
		"port":    port,
	}
	if id != "" {
		settings["id"] = id
	}
	if enc := strings.TrimSpace(getFirstQuery(q, "encryption")); enc != "" {
		settings["encryption"] = enc
	}
	if flow := strings.TrimSpace(getFirstQuery(q, "flow")); flow != "" {
		settings["flow"] = flow
	}

	ob := map[string]any{
		"protocol": "vless",
		"settings": settings,
	}
	if tag := decodeFragment(u.Fragment); tag != "" {
		ob["tag"] = tag
	}
	if stream := buildStreamSettings(q); stream != nil {
		ob["streamSettings"] = stream
	}
	return ob, nil, nil
}

func parseTrojanLink(raw string) (map[string]any, []string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	password := ""
	if u.User != nil {
		password = strings.TrimSpace(u.User.Username())
	}
	host, port, err := parseHostPort(u.Host, 0)
	if err != nil {
		return nil, nil, err
	}
	q := u.Query()

	settings := map[string]any{
		"address": host,
		"port":    port,
	}
	if password != "" {
		settings["password"] = password
	}

	ob := map[string]any{
		"protocol": "trojan",
		"settings": settings,
	}
	if tag := decodeFragment(u.Fragment); tag != "" {
		ob["tag"] = tag
	}
	if stream := buildStreamSettings(q); stream != nil {
		ob["streamSettings"] = stream
	}
	return ob, nil, nil
}

func decodeBase64Value(raw string) ([]byte, error) {
	if raw == "" {
		return nil, stderrors.New("empty base64")
	}
	cleaned := stripAllWhitespace(raw)
	encodings := []*base64.Encoding{
		base64.RawStdEncoding,
		base64.StdEncoding,
		base64.RawURLEncoding,
		base64.URLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		b, err := enc.DecodeString(cleaned)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = stderrors.New("invalid base64")
	}
	return nil, lastErr
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatInt(int64(t), 10)
	default:
		return ""
	}
}

func parseVMessLink(raw string) (map[string]any, []string, error) {
	rest := strings.TrimSpace(raw[len("vmess://"):])
	if rest == "" {
		return nil, nil, stderrors.New("empty vmess payload")
	}
	decoded, err := decodeBase64Value(rest)
	if err != nil {
		return nil, nil, err
	}
	var vm map[string]any
	if err := json.Unmarshal(decoded, &vm); err != nil {
		return nil, nil, err
	}

	host := strings.TrimSpace(toString(vm["add"]))
	portStr := strings.TrimSpace(toString(vm["port"]))
	id := strings.TrimSpace(toString(vm["id"]))
	tag := strings.TrimSpace(toString(vm["ps"]))
	security := strings.TrimSpace(toString(vm["scy"]))
	if security == "" {
		security = "auto"
	}

	port := 0
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	if host == "" || port == 0 {
		return nil, nil, stderrors.New("invalid vmess address/port")
	}

	settings := map[string]any{
		"address":  host,
		"port":     port,
		"id":       id,
		"security": security,
	}
	ob := map[string]any{
		"protocol": "vmess",
		"settings": settings,
	}
	if tag != "" {
		ob["tag"] = tag
	}

	q := url.Values{}
	if v := strings.TrimSpace(toString(vm["net"])); v != "" {
		q.Set("type", v)
	}
	tls := strings.TrimSpace(toString(vm["tls"]))
	if tls != "" {
		q.Set("security", tls)
	}
	if sni := strings.TrimSpace(toString(vm["sni"])); sni != "" {
		q.Set("sni", sni)
	}
	if hostHeader := strings.TrimSpace(toString(vm["host"])); hostHeader != "" {
		q.Set("host", hostHeader)
	}
	if path := strings.TrimSpace(toString(vm["path"])); path != "" {
		q.Set("path", path)
	}
	if alpn := strings.TrimSpace(toString(vm["alpn"])); alpn != "" {
		q.Set("alpn", alpn)
	}
	if fp := strings.TrimSpace(toString(vm["fp"])); fp != "" {
		q.Set("fp", fp)
	}

	if stream := buildStreamSettings(q); stream != nil {
		ob["streamSettings"] = stream
	}
	return ob, nil, nil
}

func parseShadowsocksLink(raw string) (map[string]any, []string, error) {
	// Support common formats:
	// 1) ss://BASE64(method:password)@host:port#name
	// 2) ss://method:password@host:port#name
	// 3) ss://BASE64(method:password@host:port)#name
	rest := strings.TrimSpace(raw[len("ss://"):])
	if rest == "" {
		return nil, nil, stderrors.New("empty ss link")
	}
	var fragment string
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		fragment = rest[i+1:]
		rest = rest[:i]
	}
	// Strip plugin/query; currently ignored.
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}

	method := ""
	password := ""
	serverHost := ""
	serverPort := 0

	parseMethodPasswordServer := func(s string) error {
		at := strings.LastIndexByte(s, '@')
		if at < 0 {
			return stderrors.New("invalid ss payload")
		}
		userinfo := s[:at]
		server := s[at+1:]
		host, port, err := parseHostPort(server, 0)
		if err != nil {
			return err
		}
		serverHost = host
		serverPort = port

		if strings.Contains(userinfo, ":") {
			parts := strings.SplitN(userinfo, ":", 2)
			method = parts[0]
			password = parts[1]
			return nil
		}
		decoded, err := decodeBase64Value(userinfo)
		if err != nil {
			return err
		}
		creds := string(decoded)
		parts := strings.SplitN(creds, ":", 2)
		if len(parts) != 2 {
			return stderrors.New("invalid ss credentials")
		}
		method = parts[0]
		password = parts[1]
		return nil
	}

	if strings.Contains(rest, "@") {
		if err := parseMethodPasswordServer(rest); err != nil {
			return nil, nil, err
		}
	} else {
		decoded, err := decodeBase64Value(rest)
		if err != nil {
			return nil, nil, err
		}
		if err := parseMethodPasswordServer(string(decoded)); err != nil {
			return nil, nil, err
		}
	}

	if method == "" || password == "" || serverHost == "" || serverPort == 0 {
		return nil, nil, stderrors.New("invalid ss link fields")
	}

	settings := map[string]any{
		"address":  serverHost,
		"port":     serverPort,
		"method":   method,
		"password": password,
	}
	ob := map[string]any{
		"protocol": "shadowsocks",
		"settings": settings,
	}
	if tag := decodeFragment(fragment); tag != "" {
		ob["tag"] = tag
	}
	return ob, nil, nil
}
