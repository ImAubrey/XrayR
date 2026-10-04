package metrics

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	go_errors "errors"
	"os"
	"strings"
	"time"

	applog "github.com/ImAubrey/acore/app/log"
	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/errors"
	clog "github.com/ImAubrey/acore/common/log"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/conntrack"
	feature_dns "github.com/ImAubrey/acore/features/dns"
	"github.com/ImAubrey/acore/features/extension"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/routing"
	feature_stats "github.com/ImAubrey/acore/features/stats"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type grpcService struct {
	UnimplementedMetricsServiceServer
	accessKey string
}

func newGrpcService(ctx context.Context, cfg *GrpcConfig) (*grpcService, error) {
	svc := &grpcService{
		accessKey: strings.TrimSpace(cfg.GetAccessKey()),
	}
	if svc.accessKey != "" {
		setMetricsAccessKey(svc.accessKey)
	}
	if inst := core.FromContext(ctx); inst != nil {
		setRuntimeInstance(inst)
	}

	var (
		om  outbound.Manager
		sm  feature_stats.Manager
		rt  routing.Router
		obs extension.Observatory
	)
	common.Must(core.RequireFeatures(ctx, func(omgr outbound.Manager, smgr feature_stats.Manager, cmgr conntrack.Manager, router routing.Router) {
		om = omgr
		sm = smgr
		rt = router
		setConntrackManager(cmgr)
	}))
	_ = core.OptionalFeatures(ctx, func(observatory extension.Observatory) error {
		obs = observatory
		return nil
	})
	setNodesDependencies(om, rt, obs)
	setExpvarSources(sm, obs)

	return svc, nil
}

func (s *grpcService) Register(server *grpc.Server) {
	RegisterMetricsServiceServer(server, s)
}

func (s *grpcService) checkAuth(ctx context.Context) error {
	key := strings.TrimSpace(s.accessKey)
	if key == "" {
		key = strings.TrimSpace(getMetricsAccessKey())
	}
	if key == "" {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	candidates := []string{}
	candidates = append(candidates, md.Get(strings.ToLower(metricsAccessKeyHeader))...)
	candidates = append(candidates, md.Get("x-access-key")...)
	candidates = append(candidates, md.Get("access-key")...)
	candidates = append(candidates, md.Get("access_key")...)
	for _, candidate := range candidates {
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(candidate)), []byte(key)) == 1 {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "unauthorized")
}

func (s *grpcService) GetConnections(ctx context.Context, _ *ConnectionsRequest) (*ConnectionsResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	snapshot := buildGroupedSnapshot()
	return toConnectionsResponse(snapshot), nil
}

func (s *grpcService) StreamConnections(req *ConnectionsStreamRequest, stream MetricsService_StreamConnectionsServer) error {
	if err := s.checkAuth(stream.Context()); err != nil {
		return err
	}
	interval := clampIntervalMs(req.GetIntervalMs(), 1000)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := stream.Send(toConnectionsResponse(buildGroupedSnapshot())); err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			if err := stream.Send(toConnectionsResponse(buildGroupedSnapshot())); err != nil {
				return err
			}
		}
	}
}

func (s *grpcService) CloseConnections(ctx context.Context, req *CloseConnectionsRequest) (*CloseConnectionsResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "ids required")
	}
	ids := normalizeCloseIDs(req.Ids)
	if len(ids) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ids required")
	}

	connMu.RLock()
	mgr := connManager
	connMu.RUnlock()
	if mgr == nil {
		return nil, status.Error(codes.Unavailable, "conntrack unavailable")
	}
	closer, ok := mgr.(interface{ CloseConnection(uint32) bool })
	if !ok {
		return nil, status.Error(codes.Unimplemented, "close not supported")
	}

	closed := make([]uint32, 0, len(ids))
	failed := make([]uint32, 0)
	for _, id := range ids {
		if closer.CloseConnection(id) {
			closed = append(closed, id)
		} else {
			failed = append(failed, id)
		}
	}

	return &CloseConnectionsResponse{
		Requested: uint32(len(ids)),
		Closed:    closed,
		Failed:    failed,
	}, nil
}

func (s *grpcService) GetDNSCacheStats(ctx context.Context, _ *DNSCacheStatsRequest) (*DNSCacheStatsResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}

	stats, err := loadDNSCacheStats()
	if err != nil {
		return &DNSCacheStatsResponse{
			Available: false,
			Error:     err.Error(),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	updatedAt := stats.UpdatedAt.UTC().Format(time.RFC3339)
	if stats.UpdatedAt.IsZero() {
		updatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	resp := &DNSCacheStatsResponse{
		Available:    true,
		UsageBytes:   stats.UsageBytes,
		LimitBytes:   stats.LimitBytes,
		EntryCount:   stats.EntryCount,
		ValidCount:   stats.ValidCount,
		ExpiredCount: stats.ExpiredCount,
		UsageRatio:   stats.UsageRatio,
		ValidRatio:   stats.ValidRatio,
		ExpiredRatio: stats.ExpiredRatio,
		UpdatedAt:    updatedAt,
		Stores:       make([]*DNSCacheStoreStats, 0, len(stats.Stores)),
	}
	for _, store := range stats.Stores {
		resp.Stores = append(resp.Stores, &DNSCacheStoreStats{
			Name:         store.Name,
			Type:         store.Type,
			UsageBytes:   store.UsageBytes,
			LimitBytes:   store.LimitBytes,
			EntryCount:   store.EntryCount,
			ValidCount:   store.ValidCount,
			ExpiredCount: store.ExpiredCount,
			UsageRatio:   store.UsageRatio,
			ValidRatio:   store.ValidRatio,
			ExpiredRatio: store.ExpiredRatio,
		})
	}
	return resp, nil
}

func (s *grpcService) FlushDNSCache(ctx context.Context, _ *emptypb.Empty) (*DNSCacheFlushResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if err := flushDNSCache(); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &DNSCacheFlushResponse{
		Ok:        true,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (s *grpcService) GetDNSQueryTypes(ctx context.Context, _ *emptypb.Empty) (*DNSQueryTypesResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	resp := &DNSQueryTypesResponse{
		Types: make([]*DNSQueryType, 0, len(dnsQueryTypes)),
	}
	for _, item := range dnsQueryTypes {
		resp.Types = append(resp.Types, &DNSQueryType{
			Value:     item.Value,
			Supported: item.Supported,
		})
	}
	return resp, nil
}

func (s *grpcService) QueryDNS(ctx context.Context, req *DNSQueryRequest) (*DNSQueryResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	domain := strings.TrimSpace(req.GetDomain())
	if domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain is required")
	}

	queryType, reqType, option, ok := resolveDNSQueryType(strings.TrimSpace(req.GetType()))
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unsupported dns query type: "+supportedDNSQueryTypesText())
	}
	option.OutboundTag = strings.TrimSpace(req.GetOutboundTag())

	inst := getRuntimeInstance()
	if inst == nil {
		return nil, status.Error(codes.Unavailable, "runtime instance unavailable")
	}
	client, ok := inst.GetFeature(feature_dns.ClientType()).(feature_dns.Client)
	if !ok || client == nil {
		return nil, status.Error(codes.Unavailable, "dns client unavailable")
	}

	cacheBefore := lookupDNSQueryCache(client, domain, reqType, option)
	var (
		records []string
		ttl     uint32
		err     error
	)
	if lookup, ok := client.(feature_dns.RecordQuery); ok {
		records, ttl, err = lookup.LookupRecord(domain, uint16(reqType), option)
	} else {
		if reqType != dnsmessage.TypeA && reqType != dnsmessage.TypeAAAA {
			return nil, status.Error(codes.Unavailable, "dns record query interface unavailable")
		}
		ips, lookupTTL, lookupErr := client.LookupIP(domain, option)
		ttl = lookupTTL
		err = lookupErr
		records = formatDNSQueryRecords(ips)
	}
	cacheAfter := lookupDNSQueryCache(client, domain, reqType, option)

	resp := &DNSQueryResponse{
		Ok:          err == nil || go_errors.Is(err, feature_dns.ErrEmptyResponse),
		Domain:      domain,
		Type:        queryType,
		Records:     append([]string{}, records...),
		Ttl:         ttl,
		CacheBefore: toDNSQueryCache(cacheBefore),
		CacheAfter:  toDNSQueryCache(cacheAfter),
		QueriedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if err != nil && !go_errors.Is(err, feature_dns.ErrEmptyResponse) {
		resp.Error = err.Error()
	}
	return resp, nil
}

func (s *grpcService) GetNodes(ctx context.Context, _ *emptypb.Empty) (*NodesResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	om, router, obs := getNodesDependencies()
	resp := &NodesResponse{
		Outbounds: []*NodeOutbound{},
		Groups:    []*BalancerGroup{},
		Statuses:  map[string]*NodeStatus{},
		Errors:    map[string]string{},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	statusViews := make(map[string]nodeStatusView)

	if om == nil {
		resp.Errors["outbounds"] = "outbound manager unavailable"
		return resp, nil
	}

	outbounds := listOutboundViews(om)
	for _, item := range outbounds {
		resp.Outbounds = append(resp.Outbounds, &NodeOutbound{
			Tag:  item.Tag,
			Type: item.Type,
		})
	}

	if obs != nil {
		statuses, err := fetchOutboundStatuses(obs)
		if err != nil {
			resp.Errors["statuses"] = err.Error()
		} else {
			statusViews = statuses
		}
	}

	if router != nil {
		groups, err := fetchBalancerGroups(router)
		if err != nil {
			resp.Errors["groups"] = err.Error()
		} else {
			enrichBalancerStatuses(groups, statusViews)
			if settings := getSettingsSnapshot(); len(settings.BalancerTags) > 0 {
				groups = filterGroupsByTags(groups, settings.BalancerTags)
			}
			for _, group := range groups {
				resp.Groups = append(resp.Groups, &BalancerGroup{
					Tag:              group.Tag,
					OverrideTarget:   group.OverrideTarget,
					PrincipleTargets: append([]string{}, group.PrincipleTargets...),
					Strategy:         group.Strategy,
					FallbackTag:      group.FallbackTag,
					ManualSelectable: group.ManualSelectable,
					Error:            group.Error,
				})
			}
		}
	}
	for tag, statusView := range statusViews {
		resp.Statuses[tag] = &NodeStatus{
			Alive:        statusView.Alive,
			Delay:        statusView.Delay,
			LastError:    statusView.LastError,
			LastSeenTime: statusView.LastSeenTime,
			LastTryTime:  statusView.LastTryTime,
		}
	}

	if len(resp.Errors) == 0 {
		resp.Errors = nil
	}

	return resp, nil
}

func (s *grpcService) OverrideBalancer(ctx context.Context, req *OverrideBalancerRequest) (*OverrideBalancerResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	_, router, _ := getNodesDependencies()
	if router == nil {
		return nil, status.Error(codes.Unavailable, "router unavailable")
	}
	overrider, ok := router.(routing.BalancerOverrider)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "override unsupported")
	}
	balancerTag := strings.TrimSpace(req.GetBalancerTag())
	if balancerTag == "" {
		return nil, status.Error(codes.InvalidArgument, "balancerTag is required")
	}
	if err := overrider.SetOverrideTarget(balancerTag, strings.TrimSpace(req.GetTarget())); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &OverrideBalancerResponse{Ok: true}, nil
}

func (s *grpcService) GetObservatoryProbe(ctx context.Context, _ *emptypb.Empty) (*ProbeModeResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	_, _, obs := getNodesDependencies()
	if obs == nil {
		return nil, status.Error(codes.Unavailable, "observatory unavailable")
	}
	controller, ok := obs.(interface {
		SetProbeMode(string) error
		GetProbeMode() string
	})
	if !ok {
		settings := reloadSettingsSnapshot()
		return &ProbeModeResponse{
			Ok:        true,
			Mode:      normalizeProbeMode(settings.ProbeMode),
			Supported: false,
		}, nil
	}
	return &ProbeModeResponse{
		Ok:        true,
		Mode:      controller.GetProbeMode(),
		Supported: true,
	}, nil
}

func (s *grpcService) SetObservatoryProbe(ctx context.Context, req *ProbeModeRequest) (*ProbeModeResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	_, _, obs := getNodesDependencies()
	if obs == nil {
		return nil, status.Error(codes.Unavailable, "observatory unavailable")
	}
	controller, ok := obs.(interface {
		SetProbeMode(string) error
		GetProbeMode() string
	})
	if !ok {
		normalized := normalizeProbeMode(req.GetMode())
		next, err := updateSettings(map[string]interface{}{"probeMode": normalized})
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to persist probe mode: "+err.Error())
		}
		return &ProbeModeResponse{
			Ok:        true,
			Mode:      normalizeProbeMode(next.ProbeMode),
			Supported: false,
		}, nil
	}
	if err := controller.SetProbeMode(req.GetMode()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &ProbeModeResponse{
		Ok:        true,
		Mode:      controller.GetProbeMode(),
		Supported: true,
	}, nil
}

func (s *grpcService) TriggerObservatoryProbe(ctx context.Context, _ *emptypb.Empty) (*ProbeTriggerResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	_, _, obs := getNodesDependencies()
	if obs == nil {
		return nil, status.Error(codes.Unavailable, "observatory unavailable")
	}
	trigger, ok := obs.(observatoryProbeTrigger)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "probe trigger unsupported")
	}
	count, err := trigger.TriggerProbe(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "probe trigger failed: "+err.Error())
	}
	return &ProbeTriggerResponse{
		Ok:        true,
		Scheduled: true,
		Targets:   int32(count),
	}, nil
}

func (s *grpcService) GetRules(ctx context.Context, _ *emptypb.Empty) (*RulesResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	_, router, _ := getNodesDependencies()
	if router == nil {
		return nil, status.Error(codes.Unavailable, "router unavailable")
	}
	provider, ok := router.(ruleConfigProvider)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "rules unavailable")
	}

	resp := &RulesResponse{
		Rules:     []*RuleView{},
		Balancers: []*BalancerView{},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	for _, rule := range provider.ListRuleConfigs() {
		if rule == nil {
			continue
		}
		raw := jsonToStruct(marshalProto(rule))
		resp.Rules = append(resp.Rules, &RuleView{
			RuleTag:     rule.GetRuleTag(),
			TargetTag:   rule.GetTag(),
			BalancerTag: rule.GetBalancingTag(),
			Raw:         raw,
		})
	}

	for _, balancer := range provider.ListBalancerConfigs() {
		if balancer == nil {
			continue
		}
		raw := jsonToStruct(marshalProto(balancer))
		resp.Balancers = append(resp.Balancers, &BalancerView{
			Tag:         balancer.GetTag(),
			Selectors:   append([]string{}, balancer.GetOutboundSelector()...),
			Strategy:    balancer.GetStrategy(),
			FallbackTag: balancer.GetFallbackTag(),
			Raw:         raw,
		})
	}

	return resp, nil
}

func (s *grpcService) GetRoutingConfig(ctx context.Context, req *RoutingConfigRequest) (*RoutingConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	preferred := ""
	if req != nil {
		preferred = strings.TrimSpace(req.GetPath())
	}
	config, foundRouting, err := findRoutingConfig(preferred)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	routing := map[string]interface{}{}
	if config != nil && config.Data != nil {
		if raw, ok := config.Data["routing"].(map[string]interface{}); ok {
			routing = raw
		}
	}
	routingStruct, err := structpb.NewStruct(routing)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode routing: "+err.Error())
	}
	resp := &RoutingConfigResponse{
		Path:         config.Path,
		Format:       config.Format,
		Routing:      routingStruct,
		FoundRouting: foundRouting,
	}
	return resp, nil
}

func (s *grpcService) UpdateRoutingConfig(ctx context.Context, req *UpdateRoutingConfigRequest) (*UpdateConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Routing == nil {
		return nil, status.Error(codes.InvalidArgument, "routing patch is empty")
	}
	routingMap := req.Routing.AsMap()
	raw := map[string]interface{}{"routing": routingMap}
	if _, ok := routingMap["routing"]; ok {
		raw = routingMap
	}
	patch, err := extractRoutingPatch(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	preferredPath := strings.TrimSpace(req.GetPath())
	if preferredPath == "" {
		if value, ok := routingMap["path"]; ok {
			if str, ok := value.(string); ok {
				preferredPath = strings.TrimSpace(str)
			}
		}
	}
	config, _, err := findRoutingConfig(preferredPath)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	if config == nil || config.Data == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid config: config root is empty")
	}

	root := config.Data
	if root == nil {
		root = map[string]interface{}{}
	}
	currentRouting := map[string]interface{}{}
	if rawRouting, ok := root["routing"].(map[string]interface{}); ok {
		for key, value := range rawRouting {
			currentRouting[key] = value
		}
	}
	for key, value := range patch {
		currentRouting[key] = value
	}
	root["routing"] = currentRouting

	payload, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode config: "+err.Error())
	}
	if err := ensureParentDir(config.Path); err != nil {
		return nil, status.Error(codes.Internal, "failed to write config: "+err.Error())
	}
	if err := os.WriteFile(config.Path, append(payload, '\n'), 0o644); err != nil {
		return nil, status.Error(codes.Internal, "failed to write config: "+err.Error())
	}
	return &UpdateConfigResponse{
		Ok:   true,
		Path: config.Path,
	}, nil
}

func (s *grpcService) GetOutboundsConfig(ctx context.Context, req *OutboundsConfigRequest) (*OutboundsConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	preferred := ""
	if req != nil {
		preferred = strings.TrimSpace(req.GetPath())
	}
	config, foundOutbounds, err := findOutboundsConfig(preferred)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	outbounds := []interface{}{}
	if config != nil && config.Data != nil {
		if raw, ok := config.Data["outbounds"].([]interface{}); ok {
			outbounds = raw
		}
	}
	listVal, err := structpb.NewList(outbounds)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode outbounds: "+err.Error())
	}
	resp := &OutboundsConfigResponse{
		Path:           config.Path,
		Format:         config.Format,
		Outbounds:      listVal,
		FoundOutbounds: foundOutbounds,
	}
	return resp, nil
}

func (s *grpcService) UpdateOutboundsConfig(ctx context.Context, req *UpdateOutboundsConfigRequest) (*UpdateConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Outbounds == nil {
		return nil, status.Error(codes.InvalidArgument, "outbounds must be provided")
	}
	raw := map[string]interface{}{"outbounds": req.Outbounds.AsSlice()}
	outbounds, err := extractOutbounds(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	preferredPath := strings.TrimSpace(req.GetPath())
	config, _, err := findOutboundsConfig(preferredPath)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	if config == nil || config.Data == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid config: config root is empty")
	}

	root := config.Data
	root["outbounds"] = outbounds
	payload, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode config: "+err.Error())
	}
	if err := ensureParentDir(config.Path); err != nil {
		return nil, status.Error(codes.Internal, "failed to write config: "+err.Error())
	}
	if err := os.WriteFile(config.Path, append(payload, '\n'), 0o644); err != nil {
		return nil, status.Error(codes.Internal, "failed to write config: "+err.Error())
	}
	return &UpdateConfigResponse{
		Ok:   true,
		Path: config.Path,
	}, nil
}

func (s *grpcService) GetInboundsConfig(ctx context.Context, req *InboundsConfigRequest) (*InboundsConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	preferred := ""
	if req != nil {
		preferred = strings.TrimSpace(req.GetPath())
	}
	config, foundInbounds, err := findInboundsConfig(preferred)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	inbounds := []interface{}{}
	if config != nil && config.Data != nil {
		if raw, ok := config.Data["inbounds"].([]interface{}); ok {
			inbounds = raw
		}
	}
	listVal, err := structpb.NewList(inbounds)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode inbounds: "+err.Error())
	}
	return &InboundsConfigResponse{
		Path:          config.Path,
		Format:        config.Format,
		Inbounds:      listVal,
		FoundInbounds: foundInbounds,
	}, nil
}

func (s *grpcService) UpdateInboundsConfig(ctx context.Context, req *UpdateInboundsConfigRequest) (*UpdateConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Inbounds == nil {
		return nil, status.Error(codes.InvalidArgument, "inbounds must be provided")
	}
	raw := map[string]interface{}{"inbounds": req.Inbounds.AsSlice()}
	inbounds, err := extractInbounds(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	preferredPath := strings.TrimSpace(req.GetPath())
	config, _, err := findInboundsConfig(preferredPath)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	if config == nil || config.Data == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid config: config root is empty")
	}

	root := config.Data
	root["inbounds"] = inbounds
	payload, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode config: "+err.Error())
	}
	if err := ensureParentDir(config.Path); err != nil {
		return nil, status.Error(codes.Internal, "failed to write config: "+err.Error())
	}
	if err := os.WriteFile(config.Path, append(payload, '\n'), 0o644); err != nil {
		return nil, status.Error(codes.Internal, "failed to write config: "+err.Error())
	}
	return &UpdateConfigResponse{
		Ok:   true,
		Path: config.Path,
	}, nil
}

func (s *grpcService) GetMainConfig(ctx context.Context, req *MainConfigRequest) (*MainConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	preferred := ""
	if req != nil {
		preferred = strings.TrimSpace(req.GetPath())
	}
	configs, primary, err := loadConfigCandidates(preferred)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	mainData := mergeMainConfigData(configs, primary)
	mainStruct, err := structpb.NewStruct(mainData)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode main config: "+err.Error())
	}
	resp := &MainConfigResponse{
		Main:      mainStruct,
		FoundMain: hasPrimaryConfigSections(mainData),
	}
	if primary != nil {
		resp.Path = primary.Path
		resp.Format = primary.Format
	}
	return resp, nil
}

func (s *grpcService) UpdateMainConfig(ctx context.Context, req *UpdateMainConfigRequest) (*UpdateConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Main == nil {
		return nil, status.Error(codes.InvalidArgument, "main must be provided")
	}

	preferredPath := strings.TrimSpace(req.GetPath())
	mainPatch := req.Main.AsMap()
	configs, primary, err := loadConfigCandidates(preferredPath)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	if primary == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid config: config file not found")
	}

	dirty := map[string]*configFile{}
	observatoryPatch, observatoryProvided, observatoryDefaultKey, err := extractObservatoryMainPatch(mainPatch)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if observatoryProvided {
		target, targetKey := pickMainSectionTargetConfig(configs, primary, []string{"observatory", "Observatory"}, observatoryDefaultKey)
		if target == nil {
			return nil, status.Error(codes.InvalidArgument, "invalid config: config file not found")
		}
		if target.Data == nil {
			target.Data = map[string]interface{}{}
		}
		target.Data[targetKey] = cloneJSONValue(observatoryPatch)
		if targetKey == "observatory" {
			delete(target.Data, "Observatory")
		} else if targetKey == "Observatory" {
			delete(target.Data, "observatory")
		}
		dirty[target.Path] = target
	}

	logPatch, logProvided, err := extractMainObjectPatch(mainPatch, "log")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if logProvided {
		target, targetKey := pickMainSectionTargetConfig(configs, primary, []string{"log"}, "log")
		if target == nil {
			return nil, status.Error(codes.InvalidArgument, "invalid config: config file not found")
		}
		if target.Data == nil {
			target.Data = map[string]interface{}{}
		}
		target.Data[targetKey] = cloneJSONValue(logPatch)
		dirty[target.Path] = target
	}

	metricsPatch, metricsProvided, err := extractMainObjectPatch(mainPatch, "metrics")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if metricsProvided {
		target, targetKey := pickMainSectionTargetConfig(configs, primary, []string{"metrics"}, "metrics")
		if target == nil {
			return nil, status.Error(codes.InvalidArgument, "invalid config: config file not found")
		}
		if target.Data == nil {
			target.Data = map[string]interface{}{}
		}
		target.Data[targetKey] = cloneJSONValue(metricsPatch)
		dirty[target.Path] = target
	}

	statsPatch, statsProvided, err := extractMainObjectPatch(mainPatch, "stats")
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if statsProvided {
		target, targetKey := pickMainSectionTargetConfig(configs, primary, []string{"stats"}, "stats")
		if target == nil {
			return nil, status.Error(codes.InvalidArgument, "invalid config: config file not found")
		}
		if target.Data == nil {
			target.Data = map[string]interface{}{}
		}
		target.Data[targetKey] = cloneJSONValue(statsPatch)
		dirty[target.Path] = target
	}

	if len(dirty) == 0 {
		return nil, status.Error(codes.InvalidArgument, "main patch has no editable sections")
	}

	for _, cfg := range configs {
		if cfg == nil || cfg.Path == "" {
			continue
		}
		if _, ok := dirty[cfg.Path]; !ok {
			continue
		}
		if err := writeObjectFile(cfg.Path, cfg.Data); err != nil {
			return nil, status.Error(codes.Internal, "failed to write config: "+err.Error())
		}
	}

	return &UpdateConfigResponse{
		Ok:   true,
		Path: primary.Path,
	}, nil
}

func (s *grpcService) GetObservatoryConfig(ctx context.Context, req *ObservatoryConfigRequest) (*ObservatoryConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	preferred := ""
	if req != nil {
		preferred = strings.TrimSpace(req.GetPath())
	}
	config, _, err := findObservatoryConfig(preferred)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	observatory, hasObservatory := getConfigSection(config.Data, "observatory")
	observatoryStruct, err := structpb.NewStruct(observatory)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode observatory config: "+err.Error())
	}
	return &ObservatoryConfigResponse{
		Path:             config.Path,
		Format:           config.Format,
		Observatory:      observatoryStruct,
		FoundObservatory: hasObservatory,
	}, nil
}

func (s *grpcService) UpdateObservatoryConfig(ctx context.Context, req *UpdateObservatoryConfigRequest) (*UpdateConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Observatory == nil {
		return nil, status.Error(codes.InvalidArgument, "observatory patch is empty")
	}
	preferredPath := strings.TrimSpace(req.GetPath())
	observatoryPatch := req.Observatory.AsMap()

	config, _, err := findObservatoryConfig(preferredPath)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	if config == nil || config.Data == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid config: config root is empty")
	}

	root := config.Data
	root["observatory"] = observatoryPatch
	if err := writeObjectFile(config.Path, root); err != nil {
		return nil, status.Error(codes.Internal, "failed to write config: "+err.Error())
	}
	return &UpdateConfigResponse{
		Ok:   true,
		Path: config.Path,
	}, nil
}

func (s *grpcService) GetSubscriptionConfig(ctx context.Context, req *SubscriptionConfigRequest) (*SubscriptionConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	preferred := ""
	if req != nil {
		preferred = strings.TrimSpace(req.GetPath())
	}
	config, foundSubscription, err := findSubscriptionConfig(preferred)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	subscription := map[string]interface{}{}
	if config != nil && config.Data != nil {
		if raw, ok := config.Data["subscription"].(map[string]interface{}); ok {
			subscription = raw
		}
	}
	subscriptionStruct, err := structpb.NewStruct(subscription)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode subscription config: "+err.Error())
	}
	return &SubscriptionConfigResponse{
		Path:              config.Path,
		Format:            config.Format,
		Subscription:      subscriptionStruct,
		FoundSubscription: foundSubscription,
	}, nil
}

func (s *grpcService) UpdateSubscriptionConfig(ctx context.Context, req *UpdateSubscriptionConfigRequest) (*UpdateConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	preferredPath := strings.TrimSpace(req.GetPath())
	config, _, err := findSubscriptionConfig(preferredPath)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to read config: "+err.Error())
	}
	if config == nil || config.Data == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid config: config root is empty")
	}

	if req.Subscription == nil {
		return &UpdateConfigResponse{
			Ok:   true,
			Path: config.Path,
		}, nil
	}

	root := config.Data
	switch payload := req.Subscription.Kind.(type) {
	case *structpb.Value_NullValue:
		delete(root, "subscription")
	case *structpb.Value_StructValue:
		root["subscription"] = payload.StructValue.AsMap()
	default:
		return nil, status.Error(codes.InvalidArgument, "subscription must be an object or null")
	}

	if err := writeObjectFile(config.Path, root); err != nil {
		return nil, status.Error(codes.Internal, "failed to write config: "+err.Error())
	}
	return &UpdateConfigResponse{
		Ok:   true,
		Path: config.Path,
	}, nil
}

func (s *grpcService) GetStartupInfo(ctx context.Context, _ *emptypb.Empty) (*StartupInfo, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	info, ok := core.GetStartupInfo()
	if !ok {
		return nil, status.Error(codes.NotFound, "startup info unavailable")
	}
	return &StartupInfo{
		Argv:         append([]string{}, info.Argv...),
		ConfigFiles:  append([]string{}, info.ConfigFiles...),
		ConfDir:      info.ConfDir,
		ConfigFormat: info.ConfigFormat,
		Cwd:          info.Cwd,
	}, nil
}

func (s *grpcService) GetSettings(ctx context.Context, _ *emptypb.Empty) (*GetSettingsResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	settings := reloadSettingsSnapshot()
	status := getStartupInfoStatus()
	return &GetSettingsResponse{
		Settings: toSettingsProto(settings),
		Path:     getSettingsPath(),
		StartupInfo: &StartupInfoStatus{
			Available: status.Available,
			Detail:    status.Detail,
		},
	}, nil
}

func (s *grpcService) UpdateSettings(ctx context.Context, req *UpdateSettingsRequest) (*UpdateSettingsResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Update == nil {
		return nil, status.Error(codes.InvalidArgument, "settings update is empty")
	}
	next, err := updateSettings(req.Update.AsMap())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to persist settings: "+err.Error())
	}
	return &UpdateSettingsResponse{
		Ok:       true,
		Settings: toSettingsProto(next),
	}, nil
}

func (s *grpcService) GetUIState(ctx context.Context, _ *emptypb.Empty) (*UIStateResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	path := getUIStatePath()
	var (
		state  map[string]interface{}
		format string
		err    error
	)
	if useEmbeddedUIState() {
		state, format, err = readUIStateFromSettings(path)
	} else {
		state, format, err = readUIStateFile(path)
	}
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to read ui state: "+err.Error())
	}
	stateStruct, err := structpb.NewStruct(state)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode ui state: "+err.Error())
	}
	return &UIStateResponse{
		Path:   path,
		Format: format,
		State:  stateStruct,
	}, nil
}

func (s *grpcService) UpdateUIState(ctx context.Context, req *UpdateUIStateRequest) (*UpdateUIStateResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil || req.Patch == nil {
		return nil, status.Error(codes.InvalidArgument, "ui state patch is empty")
	}
	patch := req.Patch.AsMap()
	if len(patch) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ui state patch is empty")
	}

	path := getUIStatePath()
	if useEmbeddedUIState() {
		next, format, err := writeUIStateToSettings(path, patch)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to write ui state: "+err.Error())
		}
		stateStruct, err := structpb.NewStruct(next)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to encode ui state: "+err.Error())
		}
		return &UpdateUIStateResponse{
			Ok:     true,
			Path:   path,
			Format: format,
			State:  stateStruct,
		}, nil
	}

	current, format, err := readUIStateFile(path)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to read ui state: "+err.Error())
	}
	next := mergeUIState(current, patch)
	next["updatedAt"] = time.Now().UTC().Format(time.RFC3339)
	if _, ok := next["version"]; !ok {
		next["version"] = uiStateVersion
	}
	ensureUIStateSelection(next)
	if err := persistUIStateFile(path, next); err != nil {
		return nil, status.Error(codes.Internal, "failed to write ui state: "+err.Error())
	}

	stateStruct, err := structpb.NewStruct(next)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to encode ui state: "+err.Error())
	}
	return &UpdateUIStateResponse{
		Ok:     true,
		Path:   path,
		Format: format,
		State:  stateStruct,
	}, nil
}

func (s *grpcService) RestartCore(ctx context.Context, _ *emptypb.Empty) (*RestartResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if !beginRestart() {
		return nil, status.Error(codes.Aborted, "restart in progress")
	}
	id := time.Now().UnixMilli()
	setRestartTaskStatus(&restartTaskStatus{
		ID:         id,
		Mode:       "restart",
		InProgress: true,
		Ok:         true,
	})
	config, files, format, err := buildRestartConfig()
	if err != nil {
		endRestart()
		finishRestartTaskStatus(id, "restart", err)
		return nil, status.Error(codes.InvalidArgument, "restart is not configured: "+err.Error())
	}
	resp := &RestartResponse{
		Ok:        true,
		Mode:      "inProcess",
		Scheduled: true,
		Files:     append([]string{}, files...),
		Format:    format,
		Id:        id,
	}
	go func(cfg *core.Config) {
		defer endRestart()
		if err := restartInProcess(cfg); err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to restart in process")
			finishRestartTaskStatus(id, "restart", err)
			return
		}
		finishRestartTaskStatus(id, "restart", nil)
	}(config)
	return resp, nil
}

func (s *grpcService) GetRestartStatus(ctx context.Context, req *RestartStatusRequest) (*RestartStatusResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	state := getRestartTaskStatus()
	if req != nil && req.GetId() != 0 && state != nil && state.ID != req.GetId() {
		state = nil
	}
	resp := &RestartStatusResponse{}
	if state != nil {
		resp.Restart = &RestartTaskStatus{
			Id:            state.ID,
			Mode:          state.Mode,
			InProgress:    state.InProgress,
			Ok:            state.Ok,
			Error:         state.Error,
			RolledBack:    state.RolledBack,
			RollbackOk:    state.RollbackOk,
			RollbackError: state.RollbackError,
		}
	}
	return resp, nil
}

func (s *grpcService) HotReload(ctx context.Context, req *HotReloadRequest) (*HotReloadResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	var rawTargets []string
	if req != nil {
		rawTargets = req.GetTargets()
	}
	if invalid := invalidHotReloadTargets(rawTargets); len(invalid) > 0 {
		return nil, status.Error(codes.InvalidArgument, "unsupported hot reload target(s): "+strings.Join(invalid, ", "))
	}
	targets := normalizeHotReloadTargets(rawTargets)
	if len(rawTargets) > 0 && len(targets) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no valid hot reload targets")
	}

	if !beginRestart() {
		return nil, status.Error(codes.Aborted, "restart in progress")
	}
	id := time.Now().UnixMilli()
	setRestartTaskStatus(&restartTaskStatus{
		ID:         id,
		Mode:       "hotReload",
		InProgress: true,
		Ok:         true,
	})

	config, files, format, err := buildRestartConfig()
	if err != nil {
		endRestart()
		finishRestartTaskStatus(id, "hotReload", err)
		return nil, status.Error(codes.InvalidArgument, "hot reload is not configured: "+err.Error())
	}
	if err := validateRestartConfig(config); err != nil {
		endRestart()
		finishRestartTaskStatus(id, "hotReload", err)
		return nil, status.Error(codes.InvalidArgument, "config validation failed: "+err.Error())
	}

	expandedTargets := expandHotReloadTargets(targets)
	mode := decideHotReloadMode(expandedTargets)
	resp := &HotReloadResponse{
		Ok: true,
		Id: id,
		HotReload: &HotReloadState{
			NeedsRestart: false,
			Warnings:     []string{},
		},
		Reload: &HotReloadExecution{
			Mode:      mode,
			Scheduled: true,
			Files:     append([]string{}, files...),
			Format:    format,
			Targets:   append([]string{}, targets...),
		},
	}

	go func(cfg *core.Config, effectiveTargets []string) {
		defer endRestart()
		if err := applyHotReload(cfg, effectiveTargets); err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to apply hot reload")
			finishRestartTaskStatus(id, "hotReload", err)
			return
		}
		finishRestartTaskStatus(id, "hotReload", nil)
	}(config, expandedTargets)

	return resp, nil
}

func (s *grpcService) GetLogs(ctx context.Context, req *LogsRequest) (*LogsResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	tail := clampTailCountValue(req.GetTail(), 200)
	queryLevel, queryOK, queryProvided := parseLogLevelValue(req.GetLevel())
	applyFilter := func(lines []string) []string {
		if queryProvided {
			return filterLogLinesByLevel(lines, queryLevel, queryOK)
		}
		level, ok := applog.MemoryLogLevelOverride()
		return filterLogLinesByLevel(lines, level, ok)
	}

	settings := getSettingsSnapshot()
	if strings.TrimSpace(settings.LogFile) == "" {
		lines := memoryTailLines(tail)
		lines = applyFilter(lines)
		return &LogsResponse{
			Lines:  lines,
			Path:   "memory",
			Source: "memory",
		}, nil
	}

	logPath := resolvePathFromCwd(settings.LogFile, resolveStartupCwd())
	lines, err := readLastLines(logPath, tail)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to read log file: "+err.Error())
	}
	lines = applyFilter(lines)
	return &LogsResponse{
		Lines:  lines,
		Path:   logPath,
		Source: "file",
	}, nil
}

func (s *grpcService) GetLogsConfig(ctx context.Context, _ *emptypb.Empty) (*LogsConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	levelName := "default"
	if override, ok := applog.MemoryLogLevelOverride(); ok {
		levelName = logLevelName(override)
	}
	return &LogsConfigResponse{
		Level: levelName,
		Debug: levelName == "debug",
	}, nil
}

func (s *grpcService) SetLogsConfig(ctx context.Context, req *SetLogsConfigRequest) (*LogsConfigResponse, error) {
	if err := s.checkAuth(ctx); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing config payload")
	}
	switch payload := req.Config.(type) {
	case *SetLogsConfigRequest_Level:
		level, apply, ok := parseLogLevel(payload.Level)
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "invalid log level")
		}
		if apply {
			applog.SetMemoryLogLevel(level)
		} else {
			applog.ClearMemoryLogLevelOverride()
		}
	case *SetLogsConfigRequest_Debug:
		if payload.Debug {
			applog.SetMemoryLogLevel(clog.Severity_Debug)
		} else {
			applog.ClearMemoryLogLevelOverride()
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "missing config payload")
	}

	levelName := "default"
	if override, ok := applog.MemoryLogLevelOverride(); ok {
		levelName = logLevelName(override)
	}
	return &LogsConfigResponse{
		Level: levelName,
		Debug: levelName == "debug",
	}, nil
}

func (s *grpcService) StreamLogs(req *LogsStreamRequest, stream MetricsService_StreamLogsServer) error {
	if err := s.checkAuth(stream.Context()); err != nil {
		return err
	}
	tail := clampTailCountValue(req.GetTail(), 200)
	queryLevel, queryOK, queryProvided := parseLogLevelValue(req.GetLevel())
	getFilter := func() (clog.Severity, bool) {
		if queryProvided {
			return queryLevel, queryOK
		}
		return applog.MemoryLogLevelOverride()
	}

	settings := getSettingsSnapshot()
	if strings.TrimSpace(settings.LogFile) == "" {
		lastID := int64(0)
		entries := applog.MemoryTail(tail)
		lines, newestID := memoryLinesFromEntries(entries)
		if len(lines) > 0 {
			lastID = newestID
		}
		level, ok := getFilter()
		lines = filterLogLinesByLevel(lines, level, ok)
		if err := stream.Send(&LogsEvent{Type: "init", Lines: lines}); err != nil {
			return err
		}

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stream.Context().Done():
				return nil
			case <-ticker.C:
				entries := applog.MemorySince(lastID)
				if len(entries) == 0 {
					continue
				}
				lines, newest := memoryLinesFromEntries(entries)
				if len(lines) == 0 {
					continue
				}
				lastID = newest
				level, ok := getFilter()
				lines = filterLogLinesByLevel(lines, level, ok)
				if len(lines) == 0 {
					continue
				}
				if err := stream.Send(&LogsEvent{Type: "append", Lines: lines}); err != nil {
					return err
				}
			}
		}
	}

	logPath := resolvePathFromCwd(settings.LogFile, resolveStartupCwd())
	if lines, err := readLastLines(logPath, tail); err == nil {
		level, ok := getFilter()
		lines = filterLogLinesByLevel(lines, level, ok)
		if err := stream.Send(&LogsEvent{Type: "init", Lines: lines}); err != nil {
			return err
		}
	} else {
		if err := stream.Send(&LogsEvent{Type: "error", Message: err.Error()}); err != nil {
			return err
		}
	}

	follower := newLogFollower(logPath)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			lines, err := follower.poll()
			if err != nil || len(lines) == 0 {
				continue
			}
			level, ok := getFilter()
			lines = filterLogLinesByLevel(lines, level, ok)
			if len(lines) == 0 {
				continue
			}
			if err := stream.Send(&LogsEvent{Type: "append", Lines: lines}); err != nil {
				return err
			}
		}
	}
}

func toConnectionsResponse(snapshot groupedSnapshot) *ConnectionsResponse {
	resp := &ConnectionsResponse{
		DownloadTotal: snapshot.DownloadTotal,
		UploadTotal:   snapshot.UploadTotal,
		Connections:   make([]*ConnectionGroup, 0, len(snapshot.Connections)),
	}
	for _, conn := range snapshot.Connections {
		resp.Connections = append(resp.Connections, toConnectionGroup(conn))
	}
	return resp
}

func toDNSQueryCache(in dnsQueryCacheResponse) *DNSQueryCache {
	return &DNSQueryCache{
		State:      in.State,
		TtlSeconds: in.TTLSeconds,
		Source:     in.Source,
	}
}

func toConnectionGroup(conn groupedConnView) *ConnectionGroup {
	out := &ConnectionGroup{
		Id:              conn.ID,
		Metadata:        toConnectionMetadata(conn.Metadata),
		Upload:          conn.Upload,
		Download:        conn.Download,
		Start:           conn.Start,
		Chains:          append([]string{}, conn.Chains...),
		Rule:            conn.Rule,
		RulePayload:     conn.RulePayload,
		ConnectionCount: uint32(conn.ConnectionCount),
		Details:         make([]*ConnectionDetail, 0, len(conn.Details)),
	}
	for _, detail := range conn.Details {
		out.Details = append(out.Details, toConnectionDetail(detail))
	}
	return out
}

func toConnectionDetail(detail connDetail) *ConnectionDetail {
	return &ConnectionDetail{
		Id:          detail.ID,
		Metadata:    toConnectionMetadata(detail.Metadata),
		Upload:      detail.Upload,
		Download:    detail.Download,
		Start:       detail.Start,
		LastSeen:    detail.LastSeen,
		Chains:      append([]string{}, detail.Chains...),
		Rule:        detail.Rule,
		RulePayload: detail.RulePayload,
	}
}

func toConnectionMetadata(meta connMetadata) *ConnectionMetadata {
	return &ConnectionMetadata{
		Network:         meta.Network,
		Type:            meta.Type,
		SourceIp:        meta.SourceIP,
		SourcePort:      meta.SourcePort,
		LocalIp:         meta.LocalIP,
		LocalPort:       meta.LocalPort,
		AcoreSrcIp:      meta.AcoreSrcIP,
		AcoreSrcPort:    meta.AcoreSrcPort,
		DestinationIp:   meta.DestinationIP,
		DestinationPort: meta.DestinationPort,
		Host:            meta.Host,
		InboundTag:      meta.InboundTag,
		OutboundTag:     meta.OutboundTag,
		User:            meta.User,
	}
}

func toSettingsProto(settings Settings) *MetricsSettings {
	return &MetricsSettings{
		AcoreGrpc:      settings.AcoreGrpc,
		AcoreMetrics:   settings.AcoreMetrics,
		LogFile:        settings.LogFile,
		RestartCommand: settings.RestartCommand,
		BalancerTags:   append([]string{}, settings.BalancerTags...),
		ProbeMode:      normalizeProbeMode(settings.ProbeMode),
	}
}

func clampIntervalMs(value int32, fallback int) time.Duration {
	if value <= 0 {
		return time.Duration(fallback) * time.Millisecond
	}
	ms := int(value)
	if ms < 200 {
		ms = 200
	}
	return time.Duration(ms) * time.Millisecond
}

func clampTailCountValue(value int32, fallback int) int {
	if value <= 0 {
		return fallback
	}
	if value > 2000 {
		return 2000
	}
	return int(value)
}

func parseLogLevelValue(raw string) (clog.Severity, bool, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false, false
	}
	level, apply, ok := parseLogLevel(value)
	if !ok {
		return 0, false, false
	}
	if !apply {
		return 0, false, true
	}
	return level, true, true
}

func jsonToStruct(raw json.RawMessage) *structpb.Struct {
	if len(raw) == 0 {
		return nil
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	out, err := structpb.NewStruct(decoded)
	if err != nil {
		return nil
	}
	return out
}

func init() {
	common.Must(common.RegisterConfig((*GrpcConfig)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return newGrpcService(ctx, cfg.(*GrpcConfig))
	}))
}
