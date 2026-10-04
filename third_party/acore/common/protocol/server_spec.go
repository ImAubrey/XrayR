package protocol

import (
	"github.com/ImAubrey/acore/common/net"
)

type ServerSpec struct {
	Destination net.Destination
	User        *MemoryUser
}

// IsValid reports whether the server spec contains a usable destination.
// Historically ServerSpec carried an explicit validity strategy; the current
// code only needs a lightweight sanity check to keep picker logic working.
func (s *ServerSpec) IsValid() bool {
	if s == nil {
		return false
	}
	return s.Destination.IsValid()
}

func NewServerSpec(dest net.Destination, user *MemoryUser) *ServerSpec {
	return &ServerSpec{
		Destination: dest,
		User:        user,
	}
}

func NewServerSpecFromPB(spec *ServerEndpoint) (*ServerSpec, error) {
	dest := net.TCPDestination(spec.Address.AsAddress(), net.Port(spec.Port))
	var dUser *MemoryUser
	if spec.User != nil {
		user, err := spec.User.ToMemoryUser()
		if err != nil {
			return nil, err
		}
		dUser = user
	}
	return NewServerSpec(dest, dUser), nil
}
