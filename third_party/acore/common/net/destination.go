package net

import (
	"net"
	"strings"
)

// Destination represents a network destination including address and protocol (tcp / udp).
type Destination struct {
	Address Address
	Port    Port
	Network Network
}

func safePortFromNetAddr(port int) Port {
	if port < 0 || port > 65535 {
		return Port(0)
	}
	return portFromUint32OrZero(uint32(port))
}

// DestinationFromAddr generates a Destination from a net address.
func DestinationFromAddr(addr net.Addr) Destination {
	if addr == nil {
		return Destination{}
	}
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return TCPDestination(IPAddress(addr.IP), safePortFromNetAddr(addr.Port))
	case *net.UDPAddr:
		return UDPDestination(IPAddress(addr.IP), safePortFromNetAddr(addr.Port))
	case *net.UnixAddr:
		return UnixDestination(DomainAddress(addr.Name))
	default:
		// Best-effort parse for custom net.Addr implementations. Never panic here
		// because this is used in logging/metadata paths.
		switch addr.Network() {
		case "unix", "unixgram", "unixpacket":
			return UnixDestination(DomainAddress(addr.String()))
		}
		h, p, err := SplitHostPort(addr.String())
		if err != nil {
			return Destination{}
		}
		port, err := PortFromString(p)
		if err != nil {
			return Destination{}
		}
		switch addr.Network() {
		case "udp", "udp4", "udp6":
			return UDPDestination(ParseAddress(h), port)
		default:
			return TCPDestination(ParseAddress(h), port)
		}
	}
}

// ParseDestination converts a destination from its string presentation.
func ParseDestination(dest string) (Destination, error) {
	d := Destination{
		Address: AnyIP,
		Port:    Port(0),
	}
	if strings.HasPrefix(dest, "tcp:") {
		d.Network = Network_TCP
		dest = dest[4:]
	} else if strings.HasPrefix(dest, "udp:") {
		d.Network = Network_UDP
		dest = dest[4:]
	} else if strings.HasPrefix(dest, "unix:") {
		d = UnixDestination(DomainAddress(dest[5:]))
		return d, nil
	}

	hstr, pstr, err := SplitHostPort(dest)
	if err != nil {
		return d, err
	}
	if len(hstr) > 0 {
		d.Address = ParseAddress(hstr)
	}
	if len(pstr) > 0 {
		port, err := PortFromString(pstr)
		if err != nil {
			return d, err
		}
		d.Port = port
	}
	return d, nil
}

// TCPDestination creates a TCP destination with given address
func TCPDestination(address Address, port Port) Destination {
	return Destination{
		Network: Network_TCP,
		Address: address,
		Port:    port,
	}
}

// UDPDestination creates a UDP destination with given address
func UDPDestination(address Address, port Port) Destination {
	return Destination{
		Network: Network_UDP,
		Address: address,
		Port:    port,
	}
}

// UnixDestination creates a Unix destination with given address
func UnixDestination(address Address) Destination {
	return Destination{
		Network: Network_UNIX,
		Address: address,
	}
}

// NetAddr returns the network address in this Destination in string form.
func (d Destination) NetAddr() string {
	addr := ""
	if d.Network == Network_TCP || d.Network == Network_UDP {
		addr = d.Address.String() + ":" + d.Port.String()
	} else if d.Network == Network_UNIX {
		addr = d.Address.String()
	}
	return addr
}

// RawNetAddr converts a net.Addr from its Destination presentation.
func (d Destination) RawNetAddr() net.Addr {
	var addr net.Addr
	switch d.Network {
	case Network_TCP:
		if d.Address.Family().IsIP() {
			addr = &net.TCPAddr{
				IP:   d.Address.IP(),
				Port: int(d.Port),
			}
		}
	case Network_UDP:
		if d.Address.Family().IsIP() {
			addr = &net.UDPAddr{
				IP:   d.Address.IP(),
				Port: int(d.Port),
			}
		}
	case Network_UNIX:
		if d.Address.Family().IsDomain() {
			addr = &net.UnixAddr{
				Name: d.Address.String(),
				Net:  d.Network.SystemString(),
			}
		}
	}
	return addr
}

// String returns the strings form of this Destination.
func (d Destination) String() string {
	prefix := "unknown:"
	switch d.Network {
	case Network_TCP:
		prefix = "tcp:"
	case Network_UDP:
		prefix = "udp:"
	case Network_UNIX:
		prefix = "unix:"
	}
	return prefix + d.NetAddr()
}

// IsValid returns true if this Destination is valid.
func (d Destination) IsValid() bool {
	return d.Network != Network_Unknown
}

// AsDestination converts current Endpoint into Destination.
func (p *Endpoint) AsDestination() Destination {
	return Destination{
		Network: p.Network,
		Address: p.Address.AsAddress(),
		Port:    portFromUint32OrZero(p.Port),
	}
}
