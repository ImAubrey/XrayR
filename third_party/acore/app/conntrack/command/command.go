package command

import (
	"context"
	"fmt"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/core"
	feature_conntrack "github.com/ImAubrey/acore/features/conntrack"
	"google.golang.org/grpc"
)

// conntrackServer implements ConnectionService.
type conntrackServer struct {
	manager feature_conntrack.Manager
}

func NewConntrackServer(manager feature_conntrack.Manager) ConnectionServiceServer {
	return &conntrackServer{manager: manager}
}

func (s *conntrackServer) GetConnections(ctx context.Context, request *GetConnectionsRequest) (*GetConnectionsResponse, error) {
	_ = ctx
	if s.manager == nil {
		return &GetConnectionsResponse{}, nil
	}
	snapshots := s.manager.List()

	var uploadTotal int64
	var downloadTotal int64
	for _, snap := range snapshots {
		uploadTotal += snap.Upload
		downloadTotal += snap.Download
	}

	var connections []*Connection
	if request != nil && request.PerConnection {
		connections = make([]*Connection, 0, len(snapshots))
		for _, snap := range snapshots {
			connections = append(connections, snapshotToProto(snap))
		}
	} else {
		connections = groupSnapshots(snapshots)
	}

	return &GetConnectionsResponse{
		UploadTotal:   uploadTotal,
		DownloadTotal: downloadTotal,
		Connections:   connections,
	}, nil
}

func (s *conntrackServer) mustEmbedUnimplementedConnectionServiceServer() {}

type service struct {
	manager feature_conntrack.Manager
}

func (s *service) Register(server *grpc.Server) {
	ss := NewConntrackServer(s.manager)
	RegisterConnectionServiceServer(server, ss)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := new(service)
		core.RequireFeatures(ctx, func(m feature_conntrack.Manager) {
			s.manager = m
		})
		return s, nil
	}))
}

func snapshotToProto(s feature_conntrack.Snapshot) *Connection {
	network := s.Network.SystemString()

	srcIP, srcPort := destinationIPPort(s.Source)
	dstIP, dstPort, dstDomain := destinationInfo(s)

	start := toUnixSeconds(s.Start)
	last := toUnixSeconds(s.LastSeen)

	conn := &Connection{
		Id:                s.ID,
		Network:           network,
		SourceIp:          srcIP,
		SourcePort:        srcPort,
		DestinationIp:     dstIP,
		DestinationPort:   dstPort,
		DestinationDomain: dstDomain,
		InboundTag:        s.InboundTag,
		OutboundTag:       s.OutboundTag,
		User:              s.User,
		Protocol:          s.Protocol,
		RouteTag:          s.RouteTag,
		Upload:            s.Upload,
		Download:          s.Download,
		StartTime:         start,
		LastActivity:      last,
		Connections:       1,
		Ids:               []uint32{s.ID},
	}
	return conn
}

func groupSnapshots(snaps []feature_conntrack.Snapshot) []*Connection {
	groups := make(map[string]*Connection, len(snaps))
	order := make([]string, 0, len(snaps))

	for _, snap := range snaps {
		protoConn := snapshotToProto(snap)
		key := groupKey(protoConn)
		if existing, ok := groups[key]; ok {
			existing.Upload += protoConn.Upload
			existing.Download += protoConn.Download
			existing.Connections += 1
			existing.Ids = append(existing.Ids, protoConn.Id)

			if protoConn.StartTime > 0 && (existing.StartTime == 0 || protoConn.StartTime < existing.StartTime) {
				existing.StartTime = protoConn.StartTime
			}
			if protoConn.LastActivity > existing.LastActivity {
				existing.LastActivity = protoConn.LastActivity
			}
			if existing.InboundTag == "" {
				existing.InboundTag = protoConn.InboundTag
			}
			if existing.OutboundTag == "" {
				existing.OutboundTag = protoConn.OutboundTag
			}
			if existing.User == "" {
				existing.User = protoConn.User
			}
			if existing.Protocol == "" {
				existing.Protocol = protoConn.Protocol
			}
			if existing.RouteTag == "" {
				existing.RouteTag = protoConn.RouteTag
			}
			if existing.DestinationDomain == "" {
				existing.DestinationDomain = protoConn.DestinationDomain
			}
			continue
		}
		groups[key] = protoConn
		order = append(order, key)
	}

	result := make([]*Connection, 0, len(order))
	for _, key := range order {
		result = append(result, groups[key])
	}
	return result
}

func groupKey(c *Connection) string {
	dest := c.DestinationIp
	if dest == "" {
		dest = c.DestinationDomain
	}
	return fmt.Sprintf("%s|%s|%d|%s|%d", c.Network, c.SourceIp, c.SourcePort, dest, c.DestinationPort)
}

func destinationIPPort(dest net.Destination) (string, uint32) {
	if dest.Address == nil {
		return "", 0
	}
	return dest.Address.String(), uint32(dest.Port)
}

func destinationInfo(s feature_conntrack.Snapshot) (string, uint32, string) {
	domain := ""
	if s.Destination.Address != nil && s.Destination.Address.Family().IsDomain() {
		domain = s.Destination.Address.Domain()
	}

	dest := s.Target
	if !dest.IsValid() || dest.Address == nil {
		if s.Destination.IsValid() {
			dest = s.Destination
		}
	}
	port := uint32(dest.Port)
	if port == 0 {
		port = uint32(s.Destination.Port)
	}

	ip := ""
	if dest.Address != nil {
		if dest.Address.Family().IsDomain() {
			if domain == "" {
				domain = dest.Address.Domain()
			}
		} else {
			ip = dest.Address.String()
		}
	}
	return ip, port, domain
}

func toUnixSeconds(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
