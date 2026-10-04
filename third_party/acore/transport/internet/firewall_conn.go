package internet

import (
	"net"
	"sync"

	feature_firewall "github.com/ImAubrey/acore/features/firewall"
)

type firewallObservedConn struct {
	net.Conn
	observer  feature_firewall.FlowObserver
	closeOnce sync.Once
}

func wrapConnWithFlowObserver(conn net.Conn, observer feature_firewall.FlowObserver) net.Conn {
	if conn == nil || observer == nil {
		return conn
	}
	if cloner, ok := observer.(feature_firewall.FlowObserverCloner); ok {
		observer = cloner.CloneFlowObserver()
		if observer == nil {
			return conn
		}
	}
	return &firewallObservedConn{
		Conn:     conn,
		observer: observer,
	}
}

func (c *firewallObservedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.observer != nil {
		c.observer.OnDownload(b[:n])
	}
	if err != nil {
		c.notifyClose(err)
	}
	return n, err
}

func (c *firewallObservedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && c.observer != nil {
		c.observer.OnUpload(b[:n])
	}
	if err != nil {
		c.notifyClose(err)
	}
	return n, err
}

func (c *firewallObservedConn) Close() error {
	err := c.Conn.Close()
	c.notifyClose(err)
	return err
}

func (c *firewallObservedConn) NetConn() net.Conn {
	if c == nil || c.Conn == nil {
		return nil
	}
	if wrapper, ok := c.Conn.(interface{ NetConn() net.Conn }); ok {
		return wrapper.NetConn()
	}
	return c.Conn
}

func (c *firewallObservedConn) notifyClose(err error) {
	if c == nil || c.observer == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.observer.OnClose(err)
	})
}
