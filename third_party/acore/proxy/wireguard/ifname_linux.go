//go:build linux && !android

package wireguard

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"
)

// Linux interface names are limited to IFNAMSIZ-1 (15 bytes).
const linuxIFNameMaxLen = 15

// CalculateInterfaceName returns an interface name that is very likely to be unused.
// It prefers readable sequential names (e.g. wg0, wg1, ...) and falls back to random.
func CalculateInterfaceName(prefix string) string {
	if prefix == "" {
		prefix = "wg"
	}
	if len(prefix) > linuxIFNameMaxLen {
		prefix = prefix[:linuxIFNameMaxLen]
	}

	// Try sequential names first.
	for i := 0; i < 1024; i++ {
		suffix := strconv.Itoa(i)
		baseMax := linuxIFNameMaxLen - len(suffix)
		if baseMax <= 0 {
			continue
		}
		base := prefix
		if len(base) > baseMax {
			base = base[:baseMax]
		}
		name := base + suffix
		if _, err := net.InterfaceByName(name); err != nil {
			return name
		}
	}

	// Random fallback.
	for i := 0; i < 16; i++ {
		// 4 bytes => 8 hex chars; base will be truncated to keep <= 15.
		var b [4]byte
		_, _ = rand.Read(b[:])
		suffix := hex.EncodeToString(b[:])
		baseMax := linuxIFNameMaxLen - len(suffix)
		if baseMax <= 0 {
			return suffix[:linuxIFNameMaxLen]
		}
		base := prefix
		if len(base) > baseMax {
			base = base[:baseMax]
		}
		name := base + suffix
		if _, err := net.InterfaceByName(name); err != nil {
			return name
		}
	}

	// Worst-case: just truncate prefix.
	return prefix
}
