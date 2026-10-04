package inbound

import (
	"context"
	"sync"
	"time"

	"github.com/ImAubrey/acore/app/proxyman"
	"github.com/ImAubrey/acore/common/dice"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/common/mux"
	"github.com/ImAubrey/acore/common/net"
	"github.com/ImAubrey/acore/common/task"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/proxy"
	"github.com/ImAubrey/acore/transport/internet"
)

const (
	defaultAllocRefresh     = 5 // minutes
	defaultAllocConcurrency = 3 // workers
)

func getAllocationRefresh(rc *proxyman.ReceiverConfig) uint32 {
	if rc == nil {
		return defaultAllocRefresh
	}
	// AllocationStrategy field removed in current proto; keep compatibility with legacy default.
	return defaultAllocRefresh
}

func getAllocationConcurrency(rc *proxyman.ReceiverConfig) uint32 {
	if rc == nil {
		return defaultAllocConcurrency
	}
	return defaultAllocConcurrency
}

func getEffectiveSniffing(rc *proxyman.ReceiverConfig) *proxyman.SniffingConfig {
	if rc == nil {
		return nil
	}
	return rc.SniffingSettings
}

type DynamicInboundHandler struct {
	tag            string
	v              *core.Instance
	proxyConfig    interface{}
	receiverConfig *proxyman.ReceiverConfig
	streamSettings *internet.MemoryStreamConfig
	portMutex      sync.Mutex
	portsInUse     map[net.Port]struct{}
	workerMutex    sync.RWMutex
	worker         []worker
	lastRefresh    time.Time
	mux            *mux.Server
	task           *task.Periodic

	ctx context.Context
}

func NewDynamicInboundHandler(ctx context.Context, tag string, receiverConfig *proxyman.ReceiverConfig, proxyConfig interface{}) (*DynamicInboundHandler, error) {
	v := core.MustFromContext(ctx)
	h := &DynamicInboundHandler{
		tag:            tag,
		proxyConfig:    proxyConfig,
		receiverConfig: receiverConfig,
		portsInUse:     make(map[net.Port]struct{}),
		mux:            mux.NewServer(ctx),
		v:              v,
		ctx:            ctx,
	}

	mss, err := internet.ToMemoryStreamConfig(receiverConfig.StreamSettings)
	if err != nil {
		return nil, errors.New("failed to parse stream settings").Base(err).AtWarning()
	}
	if receiverConfig.ReceiveOriginalDestination {
		if mss.SocketSettings == nil {
			mss.SocketSettings = &internet.SocketConfig{}
		}
		if mss.SocketSettings.Tproxy == internet.SocketConfig_Off {
			mss.SocketSettings.Tproxy = internet.SocketConfig_Redirect
		}
		mss.SocketSettings.ReceiveOriginalDestAddress = true
	}

	h.streamSettings = mss

	h.task = &task.Periodic{
		Interval: time.Minute * time.Duration(getAllocationRefresh(h.receiverConfig)),
		Execute:  h.refresh,
	}

	return h, nil
}

func (h *DynamicInboundHandler) allocatePort() net.Port {
	allPorts := []int32{}
	for _, pr := range h.receiverConfig.PortList.Range {
		for i := pr.From; i <= pr.To; i++ {
			allPorts = append(allPorts, int32(i))
		}
	}
	h.portMutex.Lock()
	defer h.portMutex.Unlock()

	for {
		r := dice.Roll(len(allPorts))
		port := net.Port(allPorts[r])
		_, used := h.portsInUse[port]
		if !used {
			h.portsInUse[port] = struct{}{}
			return port
		}
	}
}

func (h *DynamicInboundHandler) closeWorkers(workers []worker) {
	ports2Del := make([]net.Port, len(workers))
	for idx, worker := range workers {
		ports2Del[idx] = worker.Port()
		if err := worker.Close(); err != nil {
			errors.LogInfoInner(h.ctx, err, "failed to close worker")
		}
	}

	h.portMutex.Lock()
	for _, port := range ports2Del {
		delete(h.portsInUse, port)
	}
	h.portMutex.Unlock()
}

func (h *DynamicInboundHandler) refresh() error {
	h.lastRefresh = time.Now()

	timeout := time.Minute * time.Duration(getAllocationRefresh(h.receiverConfig)) * 2
	concurrency := getAllocationConcurrency(h.receiverConfig)
	workers := make([]worker, 0, concurrency)

	address := h.receiverConfig.Listen.AsAddress()
	if address == nil {
		address = net.AnyIP
	}

	uplinkCounter, downlinkCounter := getStatCounter(h.v, h.tag)

	for i := uint32(0); i < concurrency; i++ {
		port := h.allocatePort()
		rawProxy, err := core.CreateObject(h.v, h.proxyConfig)
		if err != nil {
			errors.LogWarningInner(h.ctx, err, "failed to create proxy instance")
			continue
		}
		p := rawProxy.(proxy.Inbound)
		nl := p.Network()
		if net.HasNetwork(nl, net.Network_TCP) {
			worker := &tcpWorker{
				tag:             h.tag,
				address:         address,
				port:            port,
				proxy:           p,
				stream:          h.streamSettings,
				recvOrigDest:    h.receiverConfig.ReceiveOriginalDestination,
				dispatcher:      h.mux,
				sniffingConfig:  getEffectiveSniffing(h.receiverConfig),
				uplinkCounter:   uplinkCounter,
				downlinkCounter: downlinkCounter,
				ctx:             h.ctx,
			}
			if err := worker.Start(); err != nil {
				errors.LogWarningInner(h.ctx, err, "failed to create TCP worker")
				continue
			}
			workers = append(workers, worker)
		}

		if net.HasNetwork(nl, net.Network_UDP) {
			worker := &udpWorker{
				tag:             h.tag,
				proxy:           p,
				address:         address,
				port:            port,
				dispatcher:      h.mux,
				sniffingConfig:  getEffectiveSniffing(h.receiverConfig),
				uplinkCounter:   uplinkCounter,
				downlinkCounter: downlinkCounter,
				stream:          h.streamSettings,
				ctx:             h.ctx,
			}
			if err := worker.Start(); err != nil {
				errors.LogWarningInner(h.ctx, err, "failed to create UDP worker")
				continue
			}
			workers = append(workers, worker)
		}
	}

	h.workerMutex.Lock()
	h.worker = workers
	h.workerMutex.Unlock()

	time.AfterFunc(timeout, func() {
		h.closeWorkers(workers)
	})

	return nil
}

func (h *DynamicInboundHandler) Start() error {
	return h.task.Start()
}

func (h *DynamicInboundHandler) Close() error {
	return h.task.Close()
}

func (h *DynamicInboundHandler) GetRandomInboundProxy() (interface{}, net.Port, int) {
	h.workerMutex.RLock()
	defer h.workerMutex.RUnlock()

	if len(h.worker) == 0 {
		return nil, 0, 0
	}
	w := h.worker[dice.Roll(len(h.worker))]
	expire := getAllocationRefresh(h.receiverConfig) - uint32(time.Since(h.lastRefresh)/time.Minute)
	return w.Proxy(), w.Port(), int(expire)
}

func (h *DynamicInboundHandler) Tag() string {
	return h.tag
}
