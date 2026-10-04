package api

import "testing"

func TestCanonicalNodeType(t *testing.T) {
	tests := []struct {
		name        string
		nodeType    string
		enableVless bool
		want        string
	}{
		{name: "v2ray", nodeType: "V2ray", want: "v2ray"},
		{name: "vless over v2ray", nodeType: "V2ray", enableVless: true, want: "vless"},
		{name: "explicit vless", nodeType: "Vless", want: "vless"},
		{name: "hy2 alias", nodeType: "Hysteria2", want: NodeTypeHY2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanonicalNodeType(tt.nodeType, tt.enableVless); got != tt.want {
				t.Fatalf("CanonicalNodeType() = %q, want %q", got, tt.want)
			}
		})
	}
}
