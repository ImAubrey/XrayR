package trojan_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/protocol/trojan"
)

func appendTLSExt(exts []byte, extType uint16, data []byte) []byte {
	exts = append(exts, byte(extType>>8), byte(extType))
	exts = append(exts, byte(len(data)>>8), byte(len(data)))
	exts = append(exts, data...)
	return exts
}

func buildSNIExtData(host string) []byte {
	name := []byte(host)
	listLen := 1 + 2 + len(name) // NameType + NameLen + Name
	d := make([]byte, 0, 2+listLen)
	d = append(d, byte(listLen>>8), byte(listLen))
	d = append(d, 0x00, byte(len(name)>>8), byte(len(name)))
	d = append(d, name...)
	return d
}

func buildTLSClientHelloRecord(host string, addALPN bool, addGREASE bool, cipherSuites int) []byte {
	if cipherSuites <= 0 {
		cipherSuites = 10
	}

	// ClientHello body (after handshake header).
	body := make([]byte, 0, 256)
	body = append(body, 0x03, 0x03)          // client_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id_len

	// Cipher suites.
	suites := make([]byte, 0, cipherSuites*2)
	for i := 0; i < cipherSuites; i++ {
		// Use non-GREASE values in a deterministic way.
		v := uint16(0x000a + i) // 0x000a, 0x000b, ...
		suites = append(suites, byte(v>>8), byte(v))
	}
	body = append(body, byte(len(suites)>>8), byte(len(suites)))
	body = append(body, suites...)

	// Compression methods: null.
	body = append(body, 0x01, 0x00)

	// Extensions.
	exts := make([]byte, 0, 128)
	if host != "" {
		exts = appendTLSExt(exts, 0x0000, buildSNIExtData(host))
	}
	if addALPN {
		exts = appendTLSExt(exts, 0x0010, []byte{})
	}
	if addGREASE {
		exts = appendTLSExt(exts, 0x0a0a, []byte{})
	}
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	// Handshake.
	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x01) // ClientHello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	// TLS record.
	record := make([]byte, 0, 5+len(handshake))
	record = append(record, 0x16, 0x03, 0x01, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)
	return record
}

func splitTLSHandshakeIntoTwoRecords(record []byte, split int) []byte {
	if len(record) < 5 {
		return record
	}
	handshake := record[5:]
	if split <= 0 || split >= len(handshake) {
		return record
	}
	frag := make([]byte, 0, len(record)+10)
	frag = append(frag, 0x16, 0x03, 0x01, byte(split>>8), byte(split))
	frag = append(frag, handshake[:split]...)
	rest := len(handshake) - split
	frag = append(frag, 0x16, 0x03, 0x01, byte(rest>>8), byte(rest))
	frag = append(frag, handshake[split:]...)
	return frag
}

func TestSniffTrojanMatches(t *testing.T) {
	b := buildTLSClientHelloRecord("example.com", false, false, 10)
	h, err := trojan.SniffTrojan(b)
	if err != nil {
		t.Fatalf("expected match, got error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header")
	}
}

func TestSniffTrojanRejectsALPN(t *testing.T) {
	b := buildTLSClientHelloRecord("example.com", true, false, 10)
	h, err := trojan.SniffTrojan(b)
	if err == nil || h != nil {
		t.Fatalf("expected reject, got header=%v err=%v", h, err)
	}
}

func TestSniffTrojanRejectsGREASE(t *testing.T) {
	b := buildTLSClientHelloRecord("example.com", false, true, 10)
	h, err := trojan.SniffTrojan(b)
	if err == nil || h != nil {
		t.Fatalf("expected reject, got header=%v err=%v", h, err)
	}
}

func TestSniffTrojanNeedMoreDataOnFragmentedHandshake(t *testing.T) {
	full := buildTLSClientHelloRecord("example.com", false, false, 10)
	frag2 := splitTLSHandshakeIntoTwoRecords(full, 8)
	frag1 := frag2[:5+8] // first record only (complete record, but incomplete handshake)
	if _, err := trojan.SniffTrojan(frag1); err != protocol.ErrProtoNeedMoreData {
		t.Fatalf("expected ErrProtoNeedMoreData, got: %v", err)
	}

	h, err := trojan.SniffTrojan(frag2)
	if err != nil {
		t.Fatalf("expected fragmented records to match, got error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header for fragmented records")
	}
}
