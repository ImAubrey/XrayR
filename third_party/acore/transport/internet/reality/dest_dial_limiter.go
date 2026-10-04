package reality

import (
	"context"
	"math"
	"net"
	"strconv"
	"sync"

	"github.com/ImAubrey/acore/common/platform"
	"golang.org/x/time/rate"
)

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type destDialLimiter struct {
	sem  chan struct{}
	rate *rate.Limiter
}

var (
	realityDestDialMaxConcurrency = platform.NewEnvFlag(platform.RealityDestDialMaxConcurrency).GetValueAsInt(0)
	realityDestDialMaxQPS         = parseRealityDestDialMaxQPS()

	realityDestDialLimiters sync.Map // map[string]*destDialLimiter, keyed by address
)

func parseRealityDestDialMaxQPS() float64 {
	raw := platform.NewEnvFlag(platform.RealityDestDialMaxQPS).GetValue(func() string { return "" })
	if raw == "" {
		return 0
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func getDestDialLimiter(address string) *destDialLimiter {
	if realityDestDialMaxConcurrency <= 0 && realityDestDialMaxQPS <= 0 {
		return nil
	}
	if v, ok := realityDestDialLimiters.Load(address); ok {
		return v.(*destDialLimiter)
	}

	var sem chan struct{}
	if realityDestDialMaxConcurrency > 0 {
		sem = make(chan struct{}, realityDestDialMaxConcurrency)
	}

	var rl *rate.Limiter
	if realityDestDialMaxQPS > 0 {
		// Burst is kept small on purpose; this is a safety knob, not a throughput boost.
		burst := int(math.Ceil(realityDestDialMaxQPS))
		if burst < 1 {
			burst = 1
		}
		rl = rate.NewLimiter(rate.Limit(realityDestDialMaxQPS), burst)
	}

	l := &destDialLimiter{sem: sem, rate: rl}
	actual, _ := realityDestDialLimiters.LoadOrStore(address, l)
	return actual.(*destDialLimiter)
}

type releaseOnCloseConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *releaseOnCloseConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func limitedDialContext(base dialContextFunc) dialContextFunc {
	if realityDestDialMaxConcurrency <= 0 && realityDestDialMaxQPS <= 0 {
		return base
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		lim := getDestDialLimiter(address)
		if lim == nil {
			return base(ctx, network, address)
		}

		if lim.rate != nil {
			if err := lim.rate.Wait(ctx); err != nil {
				return nil, err
			}
		}

		release := func() {}
		if lim.sem != nil {
			select {
			case lim.sem <- struct{}{}:
				release = func() { <-lim.sem }
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		conn, err := base(ctx, network, address)
		if err != nil {
			release()
			return nil, err
		}
		if lim.sem == nil {
			return conn, nil
		}
		return &releaseOnCloseConn{Conn: conn, release: release}, nil
	}
}
