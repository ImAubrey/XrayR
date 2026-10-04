package wireguard

import (
	"io"
	"net"
	"testing"
	"time"
)

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

type addrConn struct {
	remote string
}

func (c *addrConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *addrConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *addrConn) Close() error                     { return nil }
func (c *addrConn) LocalAddr() net.Addr              { return stringAddr("127.0.0.1:0") }
func (c *addrConn) RemoteAddr() net.Addr             { return stringAddr(c.remote) }
func (c *addrConn) SetDeadline(time.Time) error      { return nil }
func (c *addrConn) SetReadDeadline(time.Time) error  { return nil }
func (c *addrConn) SetWriteDeadline(time.Time) error { return nil }

func TestBuildPeerUsersSkipsDefaultRoutes(t *testing.T) {
	peers := []*PeerConfig{{
		PublicKey:  "pk",
		AllowedIps: []string{"0.0.0.0/0", "::/0", "::0/0"},
	}}
	if got := buildPeerUsers(peers); len(got) != 0 {
		t.Fatalf("expected default routes to be ignored, got %d entries", len(got))
	}
}

func TestResolveUserEmailPrefersMostSpecificPrefix(t *testing.T) {
	s := &Server{
		peerUsers: buildPeerUsers([]*PeerConfig{
			{PublicKey: "pk1", AllowedIps: []string{"10.0.0.0/24"}},
			{PublicKey: "pk2", AllowedIps: []string{"10.0.0.2/32"}},
		}),
	}
	got := s.resolveUserEmail(&addrConn{remote: "10.0.0.2:12345"})
	if got != "wg:pk2" {
		t.Fatalf("resolveUserEmail = %q, want %q", got, "wg:pk2")
	}
}

func TestResolveUserEmailAmbiguousSamePrefix(t *testing.T) {
	s := &Server{
		peerUsers: buildPeerUsers([]*PeerConfig{
			{PublicKey: "pk1", AllowedIps: []string{"10.0.0.2/32"}},
			{PublicKey: "pk2", AllowedIps: []string{"10.0.0.2/32"}},
		}),
	}
	got := s.resolveUserEmail(&addrConn{remote: "10.0.0.2:12345"})
	if got != "10.0.0.2" {
		t.Fatalf("resolveUserEmail = %q, want %q", got, "10.0.0.2")
	}
}
