package udp

import (
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
