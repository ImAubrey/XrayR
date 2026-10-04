package socks

import (
	"bytes"
	"errors"

	"github.com/ImAubrey/acore/common"
)

type SniffHeader struct {
	protocol string
}

func (h *SniffHeader) Protocol() string {
	return h.protocol
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotSOCKS = errors.New("not socks")

func SniffSOCKS5(b []byte) (*SniffHeader, error) {
	if len(b) < 2 {
		return nil, common.ErrNoClue
	}
	if b[0] != 0x05 {
		return nil, errNotSOCKS
	}

	nMethods := int(b[1])
	if nMethods <= 0 {
		return nil, errNotSOCKS
	}
	if len(b) < 2+nMethods {
		return nil, common.ErrNoClue
	}
	return &SniffHeader{protocol: "socks5"}, nil
}

func SniffSOCKS4(b []byte) (*SniffHeader, error) {
	if len(b) < 2 {
		return nil, common.ErrNoClue
	}
	if b[0] != 0x04 {
		return nil, errNotSOCKS
	}
	if b[1] != 0x01 && b[1] != 0x02 {
		return nil, errNotSOCKS
	}
	if len(b) < 9 {
		return nil, common.ErrNoClue
	}

	if bytes.IndexByte(b[8:], 0x00) == -1 {
		return nil, common.ErrNoClue
	}
	return &SniffHeader{protocol: "socks4"}, nil
}
