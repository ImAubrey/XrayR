package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/log"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/core"
	dns_feature "github.com/ImAubrey/acore/features/dns"
	mdns "github.com/miekg/dns"

	"golang.org/x/net/dns/dnsmessage"
)

// Fqdn normalizes domain make sure it ends with '.'
// case-sensitive
func Fqdn(domain string) string {
	if len(domain) > 0 && strings.HasSuffix(domain, ".") {
		return domain
	}
	return domain + "."
}

type record struct {
	A    *IPRecord
	AAAA *IPRecord
}

// IPRecord is a cacheable item for a resolved domain
type IPRecord struct {
	ReqID     uint16
	IP        []net.IP
	Expire    time.Time
	RCode     dnsmessage.RCode
	RawHeader *dnsmessage.Header
}

// RRRecord is a cacheable item for a resolved domain and RR query type.
type RRRecord struct {
	ReqID     uint16
	Values    []string
	Expire    time.Time
	RCode     dnsmessage.RCode
	RawHeader *dnsmessage.Header
}

func (r *IPRecord) getIPs() ([]net.IP, int32, error) {
	if r == nil {
		return nil, 0, errRecordNotFound
	}

	untilExpire := time.Until(r.Expire).Seconds()
	ttl := int32(math.Ceil(untilExpire))

	if r.RCode != dnsmessage.RCodeSuccess {
		return nil, ttl, dns_feature.RCodeError(r.RCode)
	}
	if len(r.IP) == 0 {
		return nil, ttl, dns_feature.ErrEmptyResponse
	}

	return r.IP, ttl, nil
}

func (r *RRRecord) getValues() ([]string, int32, error) {
	if r == nil {
		return nil, 0, errRecordNotFound
	}

	untilExpire := time.Until(r.Expire).Seconds()
	ttl := int32(math.Ceil(untilExpire))

	if r.RCode != dnsmessage.RCodeSuccess {
		return nil, ttl, dns_feature.RCodeError(r.RCode)
	}
	if len(r.Values) == 0 {
		return nil, ttl, dns_feature.ErrEmptyResponse
	}

	return r.Values, ttl, nil
}

var errRecordNotFound = errors.New("record not found")

type dnsRequest struct {
	reqType dnsmessage.Type
	domain  string
	start   time.Time
	expire  time.Time
	msg     *dnsmessage.Message
}

func genEDNS0Options(clientIP net.IP, padding int) *dnsmessage.Resource {
	if len(clientIP) == 0 && padding == 0 {
		return nil
	}

	const EDNS0SUBNET = 0x8
	const EDNS0PADDING = 0xc

	opt := new(dnsmessage.Resource)
	common.Must(opt.Header.SetEDNS0(1350, 0xfe00, true))
	body := dnsmessage.OPTResource{}
	opt.Body = &body

	if len(clientIP) != 0 {
		var netmask int
		var family uint16

		if len(clientIP) == 4 {
			family = 1
			netmask = 24 // 24 for IPV4, 96 for IPv6
		} else {
			family = 2
			netmask = 96
		}

		b := make([]byte, 4)
		binary.BigEndian.PutUint16(b[0:], family)
		b[2] = byte(netmask)
		b[3] = 0
		switch family {
		case 1:
			ip := clientIP.To4().Mask(net.CIDRMask(netmask, net.IPv4len*8))
			needLength := (netmask + 8 - 1) / 8 // division rounding up
			b = append(b, ip[:needLength]...)
		case 2:
			ip := clientIP.Mask(net.CIDRMask(netmask, net.IPv6len*8))
			needLength := (netmask + 8 - 1) / 8 // division rounding up
			b = append(b, ip[:needLength]...)
		}

		body.Options = append(body.Options,
			dnsmessage.Option{
				Code: EDNS0SUBNET,
				Data: b,
			})
	}

	if padding != 0 {
		body.Options = append(body.Options,
			dnsmessage.Option{
				Code: EDNS0PADDING,
				Data: make([]byte, padding),
			})
	}

	return opt
}

func buildReqMsgs(domain string, option dns_feature.IPOption, reqIDGen func() uint16, reqOpts *dnsmessage.Resource) []*dnsRequest {
	var reqs []*dnsRequest

	if option.IPv4Enable {
		reqs = append(reqs, buildReqMsg(domain, dnsmessage.TypeA, reqIDGen, reqOpts))
	}

	if option.IPv6Enable {
		reqs = append(reqs, buildReqMsg(domain, dnsmessage.TypeAAAA, reqIDGen, reqOpts))
	}

	return reqs
}

func buildReqMsg(domain string, reqType dnsmessage.Type, reqIDGen func() uint16, reqOpts *dnsmessage.Resource) *dnsRequest {
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain),
		Type:  reqType,
		Class: dnsmessage.ClassINET,
	}
	msg := new(dnsmessage.Message)
	msg.Header.ID = reqIDGen()
	msg.Header.RecursionDesired = true
	msg.Questions = []dnsmessage.Question{question}
	if reqOpts != nil {
		msg.Additionals = append(msg.Additionals, *reqOpts)
	}
	return &dnsRequest{
		reqType: reqType,
		domain:  domain,
		start:   time.Now(),
		msg:     msg,
	}
}

// parseResponse parses DNS answers from the returned payload
func parseResponse(payload []byte) (*IPRecord, error) {
	var parser dnsmessage.Parser
	h, err := parser.Start(payload)
	if err != nil {
		return nil, errors.New("failed to parse DNS response").Base(err).AtWarning()
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, errors.New("failed to skip questions in DNS response").Base(err).AtWarning()
	}

	now := time.Now()
	ipRecord := &IPRecord{
		ReqID:     h.ID,
		RCode:     h.RCode,
		Expire:    now.Add(time.Second * dns_feature.DefaultTTL),
		RawHeader: &h,
	}

L:
	for {
		ah, err := parser.AnswerHeader()
		if err != nil {
			if err != dnsmessage.ErrSectionDone {
				errors.LogInfoInner(context.Background(), err, "failed to parse answer section for domain: ", ah.Name.String())
			}
			break
		}

		ttl := ah.TTL
		if ttl == 0 {
			ttl = 1
		}
		expire := now.Add(time.Duration(ttl) * time.Second)
		if ipRecord.Expire.After(expire) {
			ipRecord.Expire = expire
		}

		switch ah.Type {
		case dnsmessage.TypeA:
			ans, err := parser.AResource()
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to parse A record for domain: ", ah.Name)
				break L
			}
			ipRecord.IP = append(ipRecord.IP, net.IPAddress(ans.A[:]).IP())
		case dnsmessage.TypeAAAA:
			ans, err := parser.AAAAResource()
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to parse AAAA record for domain: ", ah.Name)
				break L
			}
			newIP := net.IPAddress(ans.AAAA[:]).IP()
			if len(newIP) == net.IPv6len {
				ipRecord.IP = append(ipRecord.IP, newIP)
			}
		default:
			if err := parser.SkipAnswer(); err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to skip answer")
				break L
			}
			continue
		}
	}

	return ipRecord, nil
}

func parseResponseRR(payload []byte, reqType dnsmessage.Type) (*RRRecord, error) {
	msg := new(mdns.Msg)
	if err := msg.Unpack(payload); err != nil {
		return nil, errors.New("failed to parse DNS response").Base(err).AtWarning()
	}

	now := time.Now()
	header := &dnsmessage.Header{
		ID:        msg.Id,
		RCode:     dnsmessage.RCode(msg.Rcode),
		Truncated: msg.Truncated,
	}
	rec := &RRRecord{
		ReqID:     msg.Id,
		RCode:     dnsmessage.RCode(msg.Rcode),
		Expire:    now.Add(time.Second * dns_feature.DefaultTTL),
		RawHeader: header,
		Values:    make([]string, 0),
	}

	for _, answer := range msg.Answer {
		if answer == nil || answer.Header() == nil {
			continue
		}
		h := answer.Header()
		ttl := h.Ttl
		if ttl == 0 {
			ttl = 1
		}
		expire := now.Add(time.Duration(ttl) * time.Second)
		if rec.Expire.After(expire) {
			rec.Expire = expire
		}
		if dnsmessage.Type(h.Rrtype) != reqType {
			continue
		}
		value := formatRRValue(answer)
		if value == "" {
			continue
		}
		rec.Values = append(rec.Values, value)
	}

	return rec, nil
}

func formatRRValue(answer mdns.RR) string {
	switch rr := answer.(type) {
	case *mdns.A:
		return rr.A.String()
	case *mdns.AAAA:
		return rr.AAAA.String()
	case *mdns.TXT:
		return strings.Join(rr.Txt, " ")
	case *mdns.CNAME:
		return rr.Target
	case *mdns.MX:
		return fmt.Sprintf("%d %s", rr.Preference, rr.Mx)
	case *mdns.NS:
		return rr.Ns
	case *mdns.SRV:
		return fmt.Sprintf("%d %d %d %s", rr.Priority, rr.Weight, rr.Port, rr.Target)
	case *mdns.PTR:
		return rr.Ptr
	case *mdns.CAA:
		return fmt.Sprintf("%d %s %s", rr.Flag, rr.Tag, rr.Value)
	case *mdns.NAPTR:
		return fmt.Sprintf("%d %d %s %s %s %s", rr.Order, rr.Preference, rr.Flags, rr.Service, rr.Regexp, rr.Replacement)
	case *mdns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d", rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
	default:
		return strings.TrimSpace(answer.String())
	}
}

// toDnsContext create a new background context with parent inbound, session and dns log
func toDnsContext(ctx context.Context, addr string) context.Context {
	dnsCtx := core.ToBackgroundDetachedContext(ctx)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
	}
	dnsCtx = session.ContextWithContent(dnsCtx, session.ContentFromContext(ctx))
	dnsCtx = log.ContextWithAccessMessage(dnsCtx, &log.AccessMessage{
		From:   "DNS",
		To:     addr,
		Status: log.AccessAccepted,
		Reason: "",
	})
	return dnsCtx
}
