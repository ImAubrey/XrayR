package wireguard_test

import (
	"testing"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/protocol/wireguard"
)

func TestSniffWireGuard(t *testing.T) {
	cases := []struct {
		name       string
		payload    []byte
		wantErr    bool
		wantNoClue bool
	}{
		{
			name:    "HandshakeInitiation",
			payload: wireguardPacket(1, 148),
		},
		{
			name:    "HandshakeResponse",
			payload: wireguardPacket(2, 92),
		},
		{
			name:    "CookieReply",
			payload: wireguardPacket(3, 64),
		},
		{
			name:    "TransportData",
			payload: wireguardPacket(4, 128),
		},
		{
			name:       "TooShortForType",
			payload:    wireguardPacket(4, 16),
			wantErr:    true,
			wantNoClue: true,
		},
		{
			name:    "UnknownType",
			payload: wireguardPacket(9, 128),
			wantErr: true,
		},
		{
			name:    "InvalidTypeEncoding",
			payload: []byte{1, 2, 0, 0, 0, 0, 0, 0},
			wantErr: true,
		},
		{
			name:       "NotEnoughHeader",
			payload:    []byte{1, 0, 0},
			wantErr:    true,
			wantNoClue: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header, err := wireguard.SniffWireGuard(tc.payload)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SniffWireGuard() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantNoClue && err != common.ErrNoClue {
				t.Fatalf("SniffWireGuard() error = %v, want common.ErrNoClue", err)
			}
			if !tc.wantErr {
				if header == nil {
					t.Fatal("SniffWireGuard() header = nil")
				}
				if got := header.Protocol(); got != "wireguard" {
					t.Fatalf("SniffWireGuard() protocol = %q, want %q", got, "wireguard")
				}
			}
		})
	}
}

func wireguardPacket(messageType byte, size int) []byte {
	p := make([]byte, size)
	if len(p) >= 4 {
		p[0] = messageType
		p[1] = 0
		p[2] = 0
		p[3] = 0
	}
	return p
}
