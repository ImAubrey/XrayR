package hysteria

import (
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"golang.org/x/crypto/blake2b"
)

const (
	salamanderPSKMinLen = 4
	salamanderSaltLen   = 8
	salamanderKeyLen    = blake2b.Size256
)

type salamanderPacketConn struct {
	net.PacketConn
	psk []byte

	randMu sync.Mutex
	rand   *rand.Rand
}

func wrapObfsPacketConn(raw net.PacketConn, obfs string, password string) (net.PacketConn, error) {
	switch strings.ToLower(obfs) {
	case "", "none":
		return raw, nil
	case "salamander":
		if len(password) < salamanderPSKMinLen {
			return nil, errors.New("salamander password is too short")
		}
		return &salamanderPacketConn{
			PacketConn: raw,
			psk:        []byte(password),
			rand:       rand.New(rand.NewSource(time.Now().UnixNano())),
		}, nil
	default:
		return nil, errors.New("unsupported hysteria obfs: ", obfs)
	}
}

func (c *salamanderPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, addr, err
		}
		if n <= salamanderSaltLen {
			continue
		}

		key := c.key(p[:salamanderSaltLen])
		payload := p[salamanderSaltLen:n]
		for i, b := range payload {
			p[i] = b ^ key[i%salamanderKeyLen]
		}
		return len(payload), addr, nil
	}
}

func (c *salamanderPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := make([]byte, len(p)+salamanderSaltLen)
	c.randMu.Lock()
	_, _ = c.rand.Read(out[:salamanderSaltLen])
	c.randMu.Unlock()

	key := c.key(out[:salamanderSaltLen])
	for i, b := range p {
		out[i+salamanderSaltLen] = b ^ key[i%salamanderKeyLen]
	}
	n, err := c.PacketConn.WriteTo(out, addr)
	if err != nil {
		return n, err
	}
	return len(p), nil
}

func (c *salamanderPacketConn) key(salt []byte) [salamanderKeyLen]byte {
	data := make([]byte, 0, len(c.psk)+len(salt))
	data = append(data, c.psk...)
	data = append(data, salt...)
	return blake2b.Sum256(data)
}
