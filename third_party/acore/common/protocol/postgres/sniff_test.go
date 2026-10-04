package postgres_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/protocol/postgres"
)

func TestSniffPostgres_StartupV3(t *testing.T) {
	// Minimal StartupMessage header: length + protocol version.
	input := []byte{
		0x00, 0x00, 0x00, 0x08, // len = 8
		0x00, 0x03, 0x00, 0x00, // protocol = 3.0
	}
	h, err := postgres.SniffPostgres(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h.Protocol() != "postgres" {
		t.Fatalf("expected protocol 'postgres', got: %q", h.Protocol())
	}
	if h.Domain() != "" {
		t.Fatalf("expected empty domain, got: %q", h.Domain())
	}
}

func TestSniffPostgres_SSLRequest(t *testing.T) {
	input := []byte{
		0x00, 0x00, 0x00, 0x08, // len = 8
		0x04, 0xd2, 0x16, 0x2f, // SSLRequest code
	}
	h, err := postgres.SniffPostgres(input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if h.Protocol() != "postgres+ssl" {
		t.Fatalf("expected protocol 'postgres+ssl', got: %q", h.Protocol())
	}
}
