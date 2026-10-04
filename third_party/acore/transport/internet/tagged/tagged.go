package tagged

import (
	"context"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/features/routing"
)

type DialFunc func(ctx context.Context, dispatcher routing.Dispatcher, dest net.Destination, tag string) (net.Conn, error)

var Dialer DialFunc
