package outbound

import (
	"encoding/binary"
	"testing"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/common/uuid"
	"github.com/ImAubrey/acore/proxy/vless"
)

func TestApplyDestVlessRouteClonesUserID(t *testing.T) {
	originalUUID := uuid.New()
	originalID := protocol.NewID(originalUUID)
	account := &vless.MemoryAccount{ID: originalID}
	user := &protocol.MemoryUser{
		Account: account,
		Level:   1,
	}
	request := &protocol.RequestHeader{User: user}
	originalBytes := append([]byte(nil), account.ID.Bytes()...)

	applyDestVlessRoute(request, net.Port(0xabcd), true)

	if request.User == user {
		t.Fatalf("expected user to be cloned")
	}

	gotAccount, ok := request.User.Account.(*vless.MemoryAccount)
	if !ok {
		t.Fatalf("expected vless account, got %T", request.User.Account)
	}
	if gotAccount == account {
		t.Fatalf("expected account to be cloned")
	}
	if got := binary.BigEndian.Uint16(gotAccount.ID.Bytes()[6:8]); got != 0xabcd {
		t.Fatalf("expected UUID route bytes to be 0xabcd, got %#x", got)
	}
	if got := account.ID.Bytes(); binary.BigEndian.Uint16(got[6:8]) == 0xabcd {
		t.Fatalf("expected original account ID to remain unchanged")
	}
	if diff := binary.BigEndian.Uint16(originalBytes[6:8]); diff == 0xabcd {
		t.Fatalf("test setup picked conflicting original UUID bytes")
	}
}
