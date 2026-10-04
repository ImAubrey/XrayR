package ech_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/protocol/ech"
)

func TestSniffECH_MinimalClientHelloWithECHExtension(t *testing.T) {
	// Minimal TLS record carrying a ClientHello with a single ECH extension (0xfe0d, len=0).
	input := []byte{
		0x16, 0x03, 0x01, 0x00, 0x33, // TLS record header: Handshake, version 3.1, len 0x33 (51)
		0x01, 0x00, 0x00, 0x2f, // Handshake header: ClientHello, len 0x2f (47)
		0x03, 0x03, // client_version
		// random (32 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // session_id_len = 0
		0x00, 0x02, // cipher_suites_len = 2
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x01,       // compression_methods_len = 1
		0x00,       // compression method: null
		0x00, 0x04, // extensions_len = 4
		0xfe, 0x0d, 0x00, 0x00, // extension: encrypted_client_hello, len=0
	}

	h, err := ech.SniffECH(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if got := h.Protocol(); got != "ech" {
		t.Fatalf("expected protocol 'ech', got: %q", got)
	}
	if got := h.Domain(); got != "" {
		t.Fatalf("expected empty domain (no override), got: %q", got)
	}
}

func TestSniffECH_ExtractsFirstALPN(t *testing.T) {
	// ClientHello with ECH extension (0xfe0d) and ALPN extension ["h3", "h2"].
	input := []byte{
		0x16, 0x03, 0x01, 0x00, 0x3f, // TLS record header: Handshake, version 3.1, len 63
		0x01, 0x00, 0x00, 0x3b, // Handshake header: ClientHello, len 59
		0x03, 0x03, // client_version
		// random (32 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // session_id_len = 0
		0x00, 0x02, // cipher_suites_len = 2
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x01,       // compression_methods_len = 1
		0x00,       // compression method: null
		0x00, 0x10, // extensions_len = 16
		0xfe, 0x0d, 0x00, 0x00, // extension: encrypted_client_hello, len=0
		0x00, 0x10, 0x00, 0x08, // extension: ALPN, len=8
		0x00, 0x06, // alpn_protocols_len = 6
		0x02, 0x68, 0x33, // "h3"
		0x02, 0x68, 0x32, // "h2"
	}

	h, err := ech.SniffECH(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if got := h.Protocol(); got != "ech" {
		t.Fatalf("expected protocol 'ech', got: %q", got)
	}
	if got := h.Domain(); got != "" {
		t.Fatalf("expected empty domain (no override), got: %q", got)
	}
	if got := h.ALPN(); got != "h3" {
		t.Fatalf("expected first ALPN 'h3', got: %q", got)
	}
}
