package metrics

import (
	"context"
	"expvar"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/app/observatory"
	"github.com/ImAubrey/acore/app/stats"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/conntrack"
	"github.com/ImAubrey/acore/features/extension"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
	feature_stats "github.com/ImAubrey/acore/features/stats"
)

var runtimeMu sync.RWMutex
var runtimeInstance *core.Instance
var expvarOnce sync.Once
var expvarMu sync.RWMutex
var expvarStatsManager feature_stats.Manager
var expvarObservatory extension.Observatory

type MetricsHandler struct {
	ohm          outbound.Manager
	statsManager feature_stats.Manager
	observatory  extension.Observatory
	connTrack    conntrack.Manager
	router       routing.Router
	tag          string
	listen       string
	tcpListener  net.Listener
	httpServer   *http.Server
	inListener   *OutboundListener
	inServer     *http.Server
}

// NewMetricsHandler creates a new MetricsHandler based on the given config.
func NewMetricsHandler(ctx context.Context, config *Config) (*MetricsHandler, error) {
	c := &MetricsHandler{
		tag:    config.Tag,
		listen: config.Listen,
	}
	setMetricsAccessKey(config.AccessKey)
	if inst := core.FromContext(ctx); inst != nil {
		setRuntimeInstance(inst)
	}
	common.Must(core.RequireFeatures(ctx, func(om outbound.Manager, sm feature_stats.Manager, cm conntrack.Manager, r routing.Router) {
		c.statsManager = sm
		c.ohm = om
		c.connTrack = cm
		c.router = r
		setConntrackManager(cm)
	}))
	_ = core.OptionalFeatures(ctx, func(observatory extension.Observatory) error {
		c.observatory = observatory
		return nil
	})
	setExpvarSources(c.statsManager, c.observatory)
	expvarOnce.Do(func() {
		expvar.Publish("stats", expvar.Func(func() interface{} {
			manager, ok := getExpvarStatsManager().(*stats.Manager)
			if !ok {
				return nil
			}
			resp := map[string]map[string]map[string]int64{
				"inbound":  {},
				"outbound": {},
				"user":     {},
			}
			manager.VisitCounters(func(name string, counter feature_stats.Counter) bool {
				nameSplit := strings.Split(name, ">>>")
				typeName, tagOrUser, direction := nameSplit[0], nameSplit[1], nameSplit[3]
				if item, found := resp[typeName][tagOrUser]; found {
					item[direction] = counter.Value()
				} else {
					resp[typeName][tagOrUser] = map[string]int64{
						direction: counter.Value(),
					}
				}
				return true
			})
			return resp
		}))
		expvar.Publish("observatory", expvar.Func(func() interface{} {
			obs := getExpvarObservatory()
			if obs == nil {
				return nil
			}
			resp := map[string]*observatory.OutboundStatus{}
			if o, err := obs.GetObservation(context.Background()); err != nil {
				return err
			} else {
				for _, x := range o.(*observatory.ObservationResult).GetStatus() {
					resp[x.OutboundTag] = x
				}
			}
			return resp
		}))
	})
	return c, nil
}

func setRuntimeInstance(inst *core.Instance) {
	runtimeMu.Lock()
	runtimeInstance = inst
	runtimeMu.Unlock()
}

func getRuntimeInstance() *core.Instance {
	runtimeMu.RLock()
	defer runtimeMu.RUnlock()
	return runtimeInstance
}

func setExpvarSources(sm feature_stats.Manager, obs extension.Observatory) {
	expvarMu.Lock()
	expvarStatsManager = sm
	expvarObservatory = obs
	expvarMu.Unlock()
}

func getExpvarStatsManager() feature_stats.Manager {
	expvarMu.RLock()
	defer expvarMu.RUnlock()
	return expvarStatsManager
}

func getExpvarObservatory() extension.Observatory {
	expvarMu.RLock()
	defer expvarMu.RUnlock()
	return expvarObservatory
}

func (p *MetricsHandler) Type() interface{} {
	return (*MetricsHandler)(nil)
}

func (p *MetricsHandler) Start() error {
	registerConnectionsRoutes()
	setNodesDependencies(p.ohm, p.router, p.observatory)
	registerNodesRoutes()
	registerRulesRoutes()
	registerRoutingConfigRoutes()
	registerSubscriptionConfigRoutes()
	registerStartupRoutes()
	registerSettingsRoutes()
	registerUIStateRoutes()
	registerControlRoutes()
	registerDNSCacheRoutes()
	registerPprofRoutesIfEnabled()
	restoreUIStateOverrides(p.router)

	handler := wrapMetricsHandler(http.DefaultServeMux)

	// direct listen a port if listen is set
	if p.listen != "" {
		TCPlistener, err := net.Listen("tcp", p.listen)
		if err != nil {
			return err
		}
		p.tcpListener = TCPlistener
		p.httpServer = &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		errors.LogInfo(context.Background(), "Metrics server listening on ", p.listen)

		go func() {
			if err := p.httpServer.Serve(TCPlistener); err != nil && err != http.ErrServerClosed {
				errors.LogErrorInner(context.Background(), err, "failed to start metrics server")
			}
		}()
	}

	listener := newOutboundListener(4)
	p.inListener = listener
	p.inServer = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := p.inServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			errors.LogErrorInner(context.Background(), err, "failed to start metrics server")
		}
	}()

	if err := p.ohm.RemoveHandler(context.Background(), p.tag); err != nil {
		errors.LogInfo(context.Background(), "failed to remove existing handler")
	}

	return p.ohm.AddHandler(context.Background(), newOutbound(p.tag, listener))
}

func (p *MetricsHandler) Close() error {
	if p.inServer != nil {
		_ = p.inServer.Close()
	}
	if p.httpServer != nil {
		_ = p.httpServer.Close()
	}
	if p.inListener != nil {
		_ = p.inListener.Close()
	}
	if p.tcpListener != nil {
		_ = p.tcpListener.Close()
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewMetricsHandler(ctx, cfg.(*Config))
	}))
}
