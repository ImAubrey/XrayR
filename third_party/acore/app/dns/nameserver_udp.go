package dns

import (
	"context"
	"encoding/binary"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/protocol/dns"
	udp_proto "github.com/ImAubrey/acore/common/protocol/udp"
	"github.com/ImAubrey/acore/common/task"
	dns_feature "github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/routing"
	"github.com/ImAubrey/acore/transport/internet/udp"
	"golang.org/x/net/dns/dnsmessage"
)

// ClassicNameServer implemented traditional UDP DNS.
type ClassicNameServer struct {
	sync.RWMutex
	cacheController *CacheController
	address         *net.Destination
	requests        map[uint16]*udpDnsRequest
	udpServer       *udp.Dispatcher
	requestsCleanup *task.Periodic
	reqID           uint32
	clientIP        net.IP
}

type udpDnsRequest struct {
	dnsRequest
	ctx context.Context
}

// NewClassicNameServer creates udp server object for remote resolving.
func NewClassicNameServer(address net.Destination, dispatcher routing.Dispatcher, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) *ClassicNameServer {
	// default to 53 if unspecific
	if address.Port == 0 {
		address.Port = net.Port(53)
	}

	s := &ClassicNameServer{
		cacheController: NewCacheController(strings.ToUpper(address.String()), disableCache, serveStale, serveExpiredTTL),
		address:         &address,
		requests:        make(map[uint16]*udpDnsRequest),
		clientIP:        clientIP,
	}
	s.requestsCleanup = &task.Periodic{
		Interval: time.Minute,
		Execute:  s.RequestsCleanup,
	}
	s.udpServer = udp.NewDispatcher(dispatcher, s.HandleResponse)

	errors.LogInfo(context.Background(), "DNS: created UDP client initialized for ", address.NetAddr())
	return s
}

// Name implements Server.
func (s *ClassicNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *ClassicNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

// RequestsCleanup clears expired items from cache
func (s *ClassicNameServer) RequestsCleanup() error {
	now := time.Now()
	s.Lock()
	defer s.Unlock()

	if len(s.requests) == 0 {
		return errors.New(s.Name(), " nothing to do. stopping...")
	}

	for id, req := range s.requests {
		if req.expire.Before(now) {
			delete(s.requests, id)
		}
	}

	if len(s.requests) == 0 {
		s.requests = make(map[uint16]*udpDnsRequest)
	}

	return nil
}

// HandleResponse handles udp response packet from remote DNS server.
func (s *ClassicNameServer) HandleResponse(ctx context.Context, packet *udp_proto.Packet) {
	payload := packet.Payload
	raw := append([]byte(nil), payload.Bytes()...)
	payload.Release()
	if len(raw) < 2 {
		errors.LogError(ctx, s.Name(), " fail to parse responded DNS udp: short response")
		return
	}
	id := binary.BigEndian.Uint16(raw[:2])

	s.Lock()
	req, ok := s.requests[id]
	if ok {
		// remove the pending request
		delete(s.requests, id)
	}
	s.Unlock()
	if !ok {
		errors.LogError(ctx, s.Name(), " cannot find the pending request")
		return
	}

	if req.reqType == dnsmessage.TypeA || req.reqType == dnsmessage.TypeAAAA {
		ipRec, err := parseResponse(raw)
		if err != nil {
			errors.LogErrorInner(ctx, err, s.Name(), " fail to parse responded DNS udp")
			return
		}
		if ipRec.RawHeader != nil && ipRec.RawHeader.Truncated && len(req.msg.Additionals) == 0 {
			if s.retryTruncatedQuery(req) {
				return
			}
		}
		s.cacheController.updateRecord(&req.dnsRequest, ipRec)
		return
	}

	rrRec, err := parseResponseRR(raw, req.reqType)
	if err != nil {
		errors.LogErrorInner(ctx, err, s.Name(), " fail to parse responded DNS udp")
		return
	}
	if rrRec.RawHeader != nil && rrRec.RawHeader.Truncated && len(req.msg.Additionals) == 0 {
		if s.retryTruncatedQuery(req) {
			return
		}
	}
	s.cacheController.updateRRRecord(&req.dnsRequest, rrRec)
}

func (s *ClassicNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

func (s *ClassicNameServer) addPendingRequest(req *udpDnsRequest) {
	s.Lock()
	id := req.msg.ID
	req.expire = time.Now().Add(time.Second * 8)
	s.requests[id] = req
	s.Unlock()
	common.Must(s.requestsCleanup.Start())
}

// getCacheController implements CachedNameserver.
func (s *ClassicNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// sendQuery implements CachedNameserver.
func (s *ClassicNameServer) sendQuery(ctx context.Context, _ chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying DNS for: ", fqdn)

	reqs := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))

	for _, req := range reqs {
		udpReq := &udpDnsRequest{
			dnsRequest: *req,
			ctx:        ctx,
		}
		s.addPendingRequest(udpReq)
		b, _ := dns.PackMessage(req.msg)
		copyDest := net.UDPDestination(s.address.Address, s.address.Port)
		b.UDP = &copyDest
		s.udpServer.Dispatch(toDnsContext(ctx, s.address.String()), *s.address, b)
	}
}

func (s *ClassicNameServer) sendQueryRecord(ctx context.Context, _ chan<- error, fqdn string, reqType dnsmessage.Type) {
	errors.LogInfo(ctx, s.Name(), " querying DNS record for: ", fqdn, " ", reqType)
	req := buildReqMsg(fqdn, reqType, s.newReqID, genEDNS0Options(s.clientIP, 0))
	udpReq := &udpDnsRequest{
		dnsRequest: *req,
		ctx:        ctx,
	}
	s.addPendingRequest(udpReq)
	b, _ := dns.PackMessage(req.msg)
	copyDest := net.UDPDestination(s.address.Address, s.address.Port)
	b.UDP = &copyDest
	s.udpServer.Dispatch(toDnsContext(ctx, s.address.String()), *s.address, b)
}

// QueryIP implements Server.
func (s *ClassicNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}

// QueryRecord queries RR records by type.
func (s *ClassicNameServer) QueryRecord(ctx context.Context, domain string, reqType dnsmessage.Type) ([]string, uint32, error) {
	return queryRecord(ctx, s, domain, reqType)
}

func (s *ClassicNameServer) retryTruncatedQuery(req *udpDnsRequest) bool {
	// copy necessary meta data from original request and add EDNS0 option
	opt := new(dnsmessage.Resource)
	common.Must(opt.Header.SetEDNS0(1350, 0xfe00, true))
	opt.Body = &dnsmessage.OPTResource{}
	newMsg := *req.msg
	newReq := *req
	newMsg.Additionals = append(newMsg.Additionals, *opt)
	newMsg.ID = s.newReqID()
	newReq.msg = &newMsg
	s.addPendingRequest(&newReq)
	b, _ := dns.PackMessage(newReq.msg)
	copyDest := net.UDPDestination(s.address.Address, s.address.Port)
	b.UDP = &copyDest
	s.udpServer.Dispatch(toDnsContext(newReq.ctx, s.address.String()), *s.address, b)
	return true
}
