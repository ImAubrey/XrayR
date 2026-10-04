package httpupgrade

import (
	"io"
	"net"
)

type connection struct {
	net.Conn
	reader     io.Reader
	remoteAddr net.Addr
}

func newConnection(conn net.Conn, remoteAddr net.Addr, reader io.Reader) *connection {
	return &connection{
		Conn:       conn,
		reader:     reader,
		remoteAddr: remoteAddr,
	}
}

func (c *connection) Read(b []byte) (int, error) {
	if c.reader != nil {
		return c.reader.Read(b)
	}
	return c.Conn.Read(b)
}

func (c *connection) RemoteAddr() net.Addr {
	return c.remoteAddr
}
