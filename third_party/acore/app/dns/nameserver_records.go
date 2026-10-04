package dns

import (
	"context"
	go_errors "errors"
	"time"

	"github.com/ImAubrey/acore/common/errors"
	"golang.org/x/net/dns/dnsmessage"
)

type RRNameserver interface {
	getCacheController() *CacheController
	sendQueryRecord(ctx context.Context, noResponseErrCh chan<- error, fqdn string, reqType dnsmessage.Type)
}

func queryRecord(ctx context.Context, s RRNameserver, domain string, reqType dnsmessage.Type) ([]string, uint32, error) {
	fqdn := Fqdn(domain)
	cache := s.getCacheController()
	if !cache.disableCache {
		if rec := cache.findRRRecord(fqdn, reqType); rec != nil {
			values, ttl, err := rec.getValues()
			if !go_errors.Is(err, errRecordNotFound) {
				if ttl > 0 {
					return values, uint32(ttl), err
				}
				if cache.serveStale && (cache.serveExpiredTTL == 0 || cache.serveExpiredTTL < ttl) {
					go pullRecord(ctx, s, fqdn, reqType)
					return values, 1, err
				}
			}
		}
	}

	return fetchRecord(ctx, s, fqdn, reqType)
}

func pullRecord(ctx context.Context, s RRNameserver, fqdn string, reqType dnsmessage.Type) {
	nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
	defer cancel()
	_, _, _ = fetchRecord(nctx, s, fqdn, reqType)
}

func fetchRecord(ctx context.Context, s RRNameserver, fqdn string, reqType dnsmessage.Type) ([]string, uint32, error) {
	key := rrPubSubKey(fqdn, reqType)
	v, _, _ := s.getCacheController().requestGroup.Do(key, func() (any, error) {
		return doFetchRecord(ctx, s, fqdn, reqType), nil
	})
	ret := v.(recordResult)
	return ret.values, ret.ttl, ret.error
}

type recordResult struct {
	values []string
	ttl    uint32
	error
}

func doFetchRecord(ctx context.Context, s RRNameserver, fqdn string, reqType dnsmessage.Type) recordResult {
	sub := s.getCacheController().registerRRSubscriber(fqdn, reqType)
	defer closeSubscribers(sub, nil)

	noResponseErrCh := make(chan error, 1)
	onEvent := func() (*RRRecord, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-noResponseErrCh:
			return nil, err
		case msg := <-sub.Wait():
			sub.Close()
			rec, ok := msg.(*RRRecord)
			if !ok {
				return nil, errors.New("invalid record response type")
			}
			return rec, nil
		}
	}

	s.sendQueryRecord(ctx, noResponseErrCh, fqdn, reqType)
	rec, err := onEvent()
	if err != nil {
		return recordResult{nil, 0, err}
	}

	values, ttl, err := rec.getValues()
	var outTTL uint32
	if ttl > 0 {
		outTTL = uint32(ttl)
	} else if ttl == 0 && go_errors.Is(err, errRecordNotFound) {
		outTTL = 0
	} else {
		outTTL = 1
	}
	return recordResult{values, outTTL, err}
}
