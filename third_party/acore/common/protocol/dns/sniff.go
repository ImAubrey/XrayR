package dns

import (
	"encoding/binary"
	"strings"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/protocol"
	"golang.org/x/net/dns/dnsmessage"
)

// SniffHeader carries DNS sniffing results.
type SniffHeader struct {
	domain string
}

// Protocol implements dispatcher.SniffResult.
func (h *SniffHeader) Protocol() string {
	return "dns"
}

// Domain implements dispatcher.SniffResult.
func (h *SniffHeader) Domain() string {
	return h.domain
}

// SniffDNS parses DNS payload and extracts query domain.
// For TCP, the payload includes a 2-byte length prefix.
func SniffDNS(b []byte, isTCP bool) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	payload := b
	if isTCP {
		if len(b) < 2 {
			return nil, protocol.ErrProtoNeedMoreData
		}
		size := int(binary.BigEndian.Uint16(b[:2]))
		if size <= 0 {
			return nil, common.ErrNoClue
		}
		if len(b) < 2+size {
			return nil, protocol.ErrProtoNeedMoreData
		}
		payload = b[2 : 2+size]
	}

	// DNS header is at least 12 bytes.
	if len(payload) < 12 {
		return nil, common.ErrNoClue
	}

	var parser dnsmessage.Parser
	if _, err := parser.Start(payload); err != nil {
		return nil, common.ErrNoClue
	}

	question, err := parser.Question()
	if err != nil {
		return nil, common.ErrNoClue
	}

	domain := strings.TrimSuffix(question.Name.String(), ".")
	domain = strings.ToLower(domain)
	if domain == "" {
		return nil, common.ErrNoClue
	}

	return &SniffHeader{domain: domain}, nil
}
