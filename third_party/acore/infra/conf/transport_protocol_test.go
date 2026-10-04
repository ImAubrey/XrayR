package conf_test

import (
	"testing"

	. "github.com/ImAubrey/acore/infra/conf"
)

func TestTransportProtocolAXPath(t *testing.T) {
	cases := []TransportProtocol{
		"axpath",
		"AXPATH",
		" axpath ",
		"\taxpath\n",
		"ax-path",
		"ax_path",
	}

	for _, c := range cases {
		got, err := c.Build()
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", string(c), err)
		}
		if got != "axpath" {
			t.Fatalf("unexpected protocol for %q: %q", string(c), got)
		}
	}
}
