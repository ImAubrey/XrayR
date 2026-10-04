package conf

import "testing"

func TestParseSendThroughHashIPv4(t *testing.T) {
	value := "hash:192.0.2.0/24"
	addr, cidr, err := parseSendThrough(&value, false)
	if err != nil {
		t.Fatalf("parseSendThrough() error = %v", err)
	}
	if addr == nil || addr.Address == nil || !addr.Address.Family().IsIPv4() {
		t.Fatalf("expected IPv4 address, got %+v", addr)
	}
	if cidr != "hash:24" {
		t.Fatalf("expected cidr hash:24, got %q", cidr)
	}
}

func TestParseSendThroughHashIPv6(t *testing.T) {
	value := "hash:2001:db8::/64"
	addr, cidr, err := parseSendThrough(&value, true)
	if err != nil {
		t.Fatalf("parseSendThrough() error = %v", err)
	}
	if addr == nil || addr.Address == nil || !addr.Address.Family().IsIPv6() {
		t.Fatalf("expected IPv6 address, got %+v", addr)
	}
	if cidr != "hash:64" {
		t.Fatalf("expected cidr hash:64, got %q", cidr)
	}
}

func TestParseSendThroughHashRequiresCIDR(t *testing.T) {
	value := "hash:192.0.2.1"
	if _, _, err := parseSendThrough(&value, false); err == nil {
		t.Fatal("expected error for hash sendThrough without CIDR")
	}
}

func TestParseSendThroughHashRequiresIP(t *testing.T) {
	value := "hash:srcip/24"
	if _, _, err := parseSendThrough(&value, false); err == nil {
		t.Fatal("expected error for hash sendThrough with non-IP address")
	}
}

func TestParseSendThroughSrcHashIPv4(t *testing.T) {
	value := "src-hash:192.0.2.0/24"
	addr, cidr, err := parseSendThrough(&value, false)
	if err != nil {
		t.Fatalf("parseSendThrough() error = %v", err)
	}
	if addr == nil || addr.Address == nil || !addr.Address.Family().IsIPv4() {
		t.Fatalf("expected IPv4 address, got %+v", addr)
	}
	if cidr != "src-hash:24" {
		t.Fatalf("expected cidr src-hash:24, got %q", cidr)
	}
}

func TestParseSendThroughSrcHashRequiresCIDR(t *testing.T) {
	value := "src-hash:192.0.2.1"
	if _, _, err := parseSendThrough(&value, false); err == nil {
		t.Fatal("expected error for src-hash sendThrough without CIDR")
	}
}
