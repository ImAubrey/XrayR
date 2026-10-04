package protocol_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/net"
	. "github.com/ImAubrey/acore/common/protocol"
)

func TestServerSpecIsValid(t *testing.T) {
	var spec *ServerSpec
	if spec.IsValid() {
		t.Error("nil spec should be invalid")
	}

	spec = NewServerSpec(net.TCPDestination(net.LocalHostIP, net.Port(1)), nil)
	if !spec.IsValid() {
		t.Error("spec should be valid")
	}
}

func TestServerSpecUser(t *testing.T) {
	user := &MemoryUser{Email: "test@example.com"}
	spec := NewServerSpec(net.TCPDestination(net.LocalHostIP, net.Port(1)), user)
	if spec.User != user {
		t.Error("user not set on server spec")
	}
	if spec.Destination.Port != 1 {
		t.Error("destination not set on server spec")
	}
}
