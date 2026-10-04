package ssh

import (
	"bytes"
	"errors"

	"github.com/ImAubrey/acore/common"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "ssh"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotSSH = errors.New("not ssh")

const maxSSHLine = 255

func SniffSSH(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	prefix := []byte("SSH-")
	if len(b) < len(prefix) {
		if bytes.Equal(b, prefix[:len(b)]) {
			return nil, common.ErrNoClue
		}
		return nil, errNotSSH
	}
	if !bytes.Equal(b[:len(prefix)], prefix) {
		return nil, errNotSSH
	}

	limit := len(b)
	if limit > maxSSHLine {
		limit = maxSSHLine
	}
	if bytes.IndexByte(b[:limit], '\n') == -1 {
		if len(b) < maxSSHLine {
			return nil, common.ErrNoClue
		}
		return nil, errNotSSH
	}

	return &SniffHeader{}, nil
}
