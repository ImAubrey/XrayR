package conntrack

import (
	"context"
	"time"

	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/features"
)

// CounterType identifies the grouping key used for active connection counters.
type CounterType uint8

const (
	CounterTypeSourceIP CounterType = iota + 1
	CounterTypeDestinationIP
	CounterTypeSourceDestinationIP
	CounterTypeSourcePrefix
	CounterTypeDestinationPrefix
)

// CounterMode identifies which connection statistic a counter represents.
type CounterMode uint8

const (
	CounterModeActiveConnections CounterMode = iota + 1
	CounterModeNewConnections
)

// CounterSnapshot is an aggregated view of connection counters for a key.
type CounterSnapshot struct {
	Mode              CounterMode
	Type              CounterType
	SourceIP          string
	DestinationIP     string
	SourcePrefix      string
	DestinationPrefix string
	Count             uint32
}

// Meta describes a connection when it is created.
type Meta struct {
	ID            uint32
	Start         time.Time
	Network       net.Network
	Source        net.Destination
	Local         net.Destination
	OutboundLocal net.Destination
	Destination   net.Destination
	Target        net.Destination
	InboundTag    string
	InboundName   string
	OutboundTag   string
	OutboundName  string
	User          string
	Protocol      string
	ALPN          string
	JA4           string
	JA4Tag        string
	DomainSource  string
	RouteTag      string
}

// Snapshot is a point-in-time view of a tracked connection.
type Snapshot struct {
	ID            uint32
	Start         time.Time
	LastSeen      time.Time
	Network       net.Network
	Source        net.Destination
	Local         net.Destination
	OutboundLocal net.Destination
	Destination   net.Destination
	Target        net.Destination
	InboundTag    string
	InboundName   string
	OutboundTag   string
	OutboundName  string
	User          string
	Protocol      string
	ALPN          string
	JA4           string
	JA4Tag        string
	DomainSource  string
	RouteTag      string
	Upload        int64
	Download      int64
}

// Connection is a live tracked connection.
type Connection interface {
	ID() uint32
	AddUpload(int64)
	AddDownload(int64)
	SetOutboundTag(string)
	SetOutboundName(string)
	SetRouteTag(string)
	SetTarget(net.Destination)
	SetOutboundLocal(net.Destination)
	SetProtocol(string)
	SetALPN(string)
	SetJA4(string)
	SetJA4Tag(string)
	SetDomainSource(string)
	Snapshot() Snapshot
	Close()
}

// Manager tracks active connections.
//
// acore:api:experimental
// (experimental until stabilized)
type Manager interface {
	features.Feature
	NewConnection(meta Meta) Connection
	List() []Snapshot
	CountConnections(counterMode CounterMode, counterType CounterType, sourceKey, destinationKey string, window time.Duration) uint32
	ListConnectionCounters(counterMode CounterMode, counterType CounterType, window time.Duration) []CounterSnapshot
}

// ManagerType returns the type of Manager interface. Can be used to implement common.HasType.
func ManagerType() interface{} {
	return (*Manager)(nil)
}

type contextKey struct{}

// ContextWithConnection stores a tracked connection in context.
func ContextWithConnection(ctx context.Context, conn Connection) context.Context {
	if conn == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, conn)
}

// ConnectionFromContext retrieves a tracked connection from context.
func ConnectionFromContext(ctx context.Context) Connection {
	if ctx == nil {
		return nil
	}
	if conn, ok := ctx.Value(contextKey{}).(Connection); ok {
		return conn
	}
	return nil
}
