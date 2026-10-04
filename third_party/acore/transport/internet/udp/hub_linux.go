//go:build linux
// +build linux

package udp

import (
	"syscall"
	"unsafe"

	"github.com/ImAubrey/acore/common/net"
	"golang.org/x/sys/unix"
)

func RetrieveOriginalDest(oob []byte) net.Destination {
	// Equivalent to syscall.ParseSocketControlMessage, but zero-allocation.
	for len(oob) >= unix.SizeofCmsghdr {
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		l := int(hdr.Len)
		if l < unix.SizeofCmsghdr || l > len(oob) {
			break
		}
		data := oob[unix.SizeofCmsghdr:l]
		if hdr.Level == syscall.SOL_IP && hdr.Type == syscall.IP_RECVORIGDSTADDR {
			if len(data) >= 8 {
				ip := net.IPAddress(data[4:8])
				port := net.PortFromBytes(data[2:4])
				return net.UDPDestination(ip, port)
			}
		} else if hdr.Level == syscall.SOL_IPV6 && hdr.Type == unix.IPV6_RECVORIGDSTADDR {
			if len(data) >= 24 {
				ip := net.IPAddress(data[8:24])
				port := net.PortFromBytes(data[2:4])
				return net.UDPDestination(ip, port)
			}
		}

		oob = oob[cmsgAlignOf(l):]
	}
	return net.Destination{}
}

func cmsgAlignOf(l int) int {
	align := int(unsafe.Sizeof(uintptr(0))) - 1
	return (l + align) & ^align
}

func ReadUDPMsg(conn *net.UDPConn, payload []byte, oob []byte) (int, int, int, *net.UDPAddr, error) {
	return conn.ReadMsgUDP(payload, oob)
}
