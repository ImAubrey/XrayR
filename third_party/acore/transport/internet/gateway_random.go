package internet

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
)

const hashedCIDRPrefix = "hash:"
const srcHashedCIDRPrefix = "src-hash:"

type gatewayHashMode uint8

const (
	gatewayHashNone gatewayHashMode = iota
	gatewayHashTargetOnly
	gatewayHashTargetWithSource
)

// CompiledSendThrough is an immutable sendThrough random-IP plan compiled from
// a fixed base address and CIDR prefix.
type CompiledSendThrough struct {
	base     net.Address
	hashMode gatewayHashMode
	network  net.IP
	hostMask []byte
}

func (c *CompiledSendThrough) active() bool {
	return c != nil && len(c.network) > 0 && len(c.hostMask) == len(c.network)
}

// ParseRandomIP returns a source IP inside the given CIDR.
// If prefix starts with "hash:", it deterministically maps the outbound target
// (domain or IP) to a stable address inside the CIDR.
// If prefix starts with "src-hash:", inbound source IP is included in hash key.
func ParseRandomIP(ctx context.Context, addr net.Address, prefix string, ob *session.Outbound) net.Address {
	if addr == nil || !addr.Family().IsIP() {
		return nil
	}
	compiled := CompileSendThrough(addr, prefix)
	if compiled == nil {
		return addr
	}
	if ip := ParseRandomIPCompiled(ctx, compiled, ob); ip != nil {
		return ip
	}
	return addr
}

// CompileSendThrough precompiles CIDR parsing and masks for sendThrough random-IP selection.
// It returns nil when prefix is empty or invalid.
func CompileSendThrough(addr net.Address, prefix string) *CompiledSendThrough {
	baseIP := normalizedGatewayIP(addr)
	if baseIP == nil {
		return nil
	}
	hashMode, ones, ok := parseGatewayPrefix(prefix)
	if !ok {
		return nil
	}
	bits := len(baseIP) * 8
	if ones < 0 || bits < ones {
		return nil
	}
	mask := net.CIDRMask(ones, bits)
	if mask == nil {
		return nil
	}
	plan := &CompiledSendThrough{
		base:     addr,
		hashMode: hashMode,
	}
	if bits == ones {
		return plan
	}
	plan.network = make(net.IP, len(baseIP))
	plan.hostMask = make([]byte, len(baseIP))
	for i := range baseIP {
		plan.network[i] = baseIP[i] & mask[i]
		plan.hostMask[i] = ^mask[i]
	}
	return plan
}

// ParseRandomIPCompiled applies a precompiled sendThrough random-IP plan.
func ParseRandomIPCompiled(ctx context.Context, compiled *CompiledSendThrough, ob *session.Outbound) net.Address {
	if compiled == nil {
		return nil
	}
	if !compiled.active() {
		return compiled.base
	}

	out := make(net.IP, len(compiled.network))
	if compiled.hashMode != gatewayHashNone {
		src := inboundSourceAddress(ctx)
		if key := gatewayHashKey(ob, compiled.hashMode == gatewayHashTargetWithSource, src); len(key) > 0 {
			hash := expandGatewayHash(key, len(out))
			applyGatewayMask(out, compiled.network, compiled.hostMask, hash)
			return net.IPAddress(out)
		}
	}

	if _, err := rand.Read(out); err != nil {
		return compiled.base
	}
	applyGatewayMask(out, compiled.network, compiled.hostMask, out)
	return net.IPAddress(out)
}

func parseGatewayPrefix(prefix string) (gatewayHashMode, int, bool) {
	cidrPrefix := strings.TrimSpace(prefix)
	if cidrPrefix == "" {
		return gatewayHashNone, 0, false
	}

	hashMode := gatewayHashNone
	switch {
	case strings.HasPrefix(strings.ToLower(cidrPrefix), srcHashedCIDRPrefix):
		hashMode = gatewayHashTargetWithSource
		cidrPrefix = strings.TrimSpace(cidrPrefix[len(srcHashedCIDRPrefix):])
	case strings.HasPrefix(strings.ToLower(cidrPrefix), hashedCIDRPrefix):
		hashMode = gatewayHashTargetOnly
		cidrPrefix = strings.TrimSpace(cidrPrefix[len(hashedCIDRPrefix):])
	}
	if cidrPrefix == "" {
		return gatewayHashNone, 0, false
	}
	ones, err := strconv.Atoi(cidrPrefix)
	if err != nil {
		return gatewayHashNone, 0, false
	}
	return hashMode, ones, true
}

func normalizedGatewayIP(addr net.Address) net.IP {
	if addr == nil || !addr.Family().IsIP() {
		return nil
	}
	ip := addr.IP()
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		out := make(net.IP, len(ip4))
		copy(out, ip4)
		return out
	}
	if ip16 := ip.To16(); ip16 != nil {
		out := make(net.IP, len(ip16))
		copy(out, ip16)
		return out
	}
	return nil
}

func applyGatewayMask(dst, network, hostMask, hostBits []byte) {
	for i := range dst {
		dst[i] = network[i] | (hostBits[i] & hostMask[i])
	}
}

func inboundSourceAddress(ctx context.Context) net.Address {
	if ctx == nil {
		return nil
	}
	inbound := session.InboundFromContext(ctx)
	if inbound == nil || !inbound.Source.IsValid() {
		return nil
	}
	addr := inbound.Source.Address
	if addr == nil || !addr.Family().IsIP() {
		return nil
	}
	return addr
}

func gatewayHashKey(ob *session.Outbound, includeSource bool, sourceAddr net.Address) []byte {
	base := outboundHashKey(ob)
	if len(base) == 0 {
		return nil
	}
	if !includeSource {
		return base
	}
	src := sourceHashKey(sourceAddr)
	if len(src) == 0 {
		return base
	}
	key := make([]byte, 0, len(base)+1+len(src))
	key = append(key, base...)
	key = append(key, '|')
	key = append(key, src...)
	return key
}

func outboundHashKey(ob *session.Outbound) []byte {
	if ob == nil {
		return nil
	}

	// Prefer domain key to keep deterministic mapping stable across DNS changes.
	for _, addr := range []net.Address{ob.RouteTarget.Address, ob.Target.Address, ob.OriginalTarget.Address} {
		if addr == nil || !addr.Family().IsDomain() {
			continue
		}
		domain := strings.TrimSpace(strings.ToLower(addr.Domain()))
		if domain == "" {
			continue
		}
		key := make([]byte, 2+len(domain))
		key[0], key[1] = 'd', ':'
		copy(key[2:], domain)
		return key
	}

	for _, addr := range []net.Address{ob.RouteTarget.Address, ob.Target.Address, ob.OriginalTarget.Address} {
		if addr == nil || !addr.Family().IsIP() {
			continue
		}
		ip := addr.IP()
		if ip == nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			key := make([]byte, 3+len(ip4))
			key[0], key[1], key[2] = 'i', '4', ':'
			copy(key[3:], ip4)
			return key
		}
		if ip16 := ip.To16(); ip16 != nil {
			key := make([]byte, 3+len(ip16))
			key[0], key[1], key[2] = 'i', '6', ':'
			copy(key[3:], ip16)
			return key
		}
	}

	return nil
}

func sourceHashKey(addr net.Address) []byte {
	if addr == nil || !addr.Family().IsIP() {
		return nil
	}
	ip := addr.IP()
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		key := make([]byte, 3+len(ip4))
		key[0], key[1], key[2] = 's', '4', ':'
		copy(key[3:], ip4)
		return key
	}
	if ip16 := ip.To16(); ip16 != nil {
		key := make([]byte, 3+len(ip16))
		key[0], key[1], key[2] = 's', '6', ':'
		copy(key[3:], ip16)
		return key
	}
	return nil
}

func expandGatewayHash(key []byte, size int) []byte {
	out := make([]byte, size)
	filled := 0
	var round byte
	for filled < size {
		h := fnv.New64a()
		_, _ = h.Write(key)
		_, _ = h.Write([]byte{round})
		var block [8]byte
		binary.BigEndian.PutUint64(block[:], h.Sum64())
		filled += copy(out[filled:], block[:])
		round++
	}
	return out
}
