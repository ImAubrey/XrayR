package encoding_test

import (
	"encoding/binary"
	"testing"

	"github.com/ImAubrey/acore/common/buf"
	. "github.com/ImAubrey/acore/proxy/vmess/encoding"
)

func TestMarshalCommandUnknown(t *testing.T) {
	buffer := buf.New()
	defer buffer.Release()

	if err := MarshalCommand(struct{}{}, buffer); err != ErrUnknownCommand {
		t.Fatalf("expected ErrUnknownCommand, got %v", err)
	}

	if err := MarshalCommand(nil, buffer); err != ErrUnknownCommand {
		t.Fatalf("expected ErrUnknownCommand for nil command, got %v", err)
	}
}

func TestUnmarshalCommandUnknown(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	auth := Authenticate(payload)
	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data[:4], auth)
	copy(data[4:], payload)

	cmd, err := UnmarshalCommand(0x01, data)
	if err != ErrUnknownCommand {
		t.Fatalf("expected ErrUnknownCommand, got %v", err)
	}
	if cmd != nil {
		t.Fatalf("expected nil command, got %v", cmd)
	}
}
