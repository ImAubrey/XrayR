package protocol_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/net"
	. "github.com/ImAubrey/acore/common/protocol"
)

func TestServerList(t *testing.T) {
	list := NewServerList()
	list.AddServer(NewServerSpec(net.TCPDestination(net.LocalHostIP, net.Port(1)), nil))
	if list.Size() != 1 {
		t.Error("list size: ", list.Size())
	}
	list.AddServer(&ServerSpec{})
	if list.Size() != 2 {
		t.Error("list.size: ", list.Size())
	}

	server := list.GetServer(1)
	if server != nil {
		t.Error("expected invalid server to be removed, got: ", server)
	}
	if list.Size() != 1 {
		t.Error("list size after removal: ", list.Size())
	}

	server = list.GetServer(0)
	if server.Destination.Port != 1 {
		t.Error("server: ", server.Destination)
	}
}

func TestServerPicker(t *testing.T) {
	list := NewServerList()
	list.AddServer(NewServerSpec(net.TCPDestination(net.LocalHostIP, net.Port(1)), nil))
	list.AddServer(NewServerSpec(net.TCPDestination(net.LocalHostIP, net.Port(2)), nil))
	list.AddServer(NewServerSpec(net.TCPDestination(net.LocalHostIP, net.Port(3)), nil))

	picker := NewRoundRobinServerPicker(list)
	server := picker.PickServer()
	if server.Destination.Port != 1 {
		t.Error("server: ", server.Destination)
	}
	server = picker.PickServer()
	if server.Destination.Port != 2 {
		t.Error("server: ", server.Destination)
	}
	server = picker.PickServer()
	if server.Destination.Port != 3 {
		t.Error("server: ", server.Destination)
	}
	server = picker.PickServer()
	if server.Destination.Port != 1 {
		t.Error("server: ", server.Destination)
	}
}
