package axpath

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	goerrors "errors"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/errors"
)

type sendSeg struct {
	frame      []byte
	payloadLen int

	sent     bool
	lastSent time.Time
	lastFlow byte

	acked    bool
	inflight int
}

type sessionRole byte

const (
	roleUnknown sessionRole = iota
	roleClient
	roleServer
)

func (r sessionRole) String() string {
	switch r {
	case roleClient:
		return "client"
	case roleServer:
		return "server"
	default:
		return "unknown"
	}
}

type session struct {
	ctx    context.Context
	cancel context.CancelFunc

	subflows          int
	chunkSize         int // max segment size (bytes)
	ackMaskBits       int // used as SACK capacity (bits); 128 bits per SACK block
	sackMaxBlocks     int
	maxInflight       int // bytes of un-ACKed data allowed
	maxQueuePerFlow   int
	joinTimeout       time.Duration
	resumeTimeout     time.Duration
	reconnectSubflows bool
	psk               string

	role      sessionRole
	createdAt time.Time

	sessionID [16]byte
	epoch     uint32

	localAddr  net.Addr
	remoteAddr net.Addr

	onClose func()

	closeOnce sync.Once

	flowsMu sync.RWMutex
	flows   map[byte]*subflow

	// Client-side only: prevents duplicate concurrent dials for the same subflow id
	// when initial join and reconnect overlap.
	dialingMask atomic.Uint32

	sendMu        sync.Mutex
	sendCond      *sync.Cond
	sendNext      uint64 // next DSN (bytes)
	lastDataAck   uint64
	lastAckAt     time.Time
	inflightBytes int
	sendWindow    map[uint64]*sendSeg // dsn -> seg
	txCh          chan uint64

	ackSignal  chan struct{}
	flowSignal chan struct{}

	recvMu     sync.Mutex
	recvNext   uint64 // next expected DSN (bytes)
	recvHold   map[uint64][]byte
	recvHoldSz int
	rq         *readQueue

	writeFrame  []byte
	writeOff    int
	writeSignal chan struct{}

	sendFramePool sync.Pool
	ackFrameCap   int
	ackFramePool  sync.Pool
	recvPool      sync.Pool

	emptyGen atomic.Uint64
	closing  atomic.Bool
}

func newSession(parent context.Context, cfg *Config) *session {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)

	now := time.Now()
	s := &session{
		ctx:               ctx,
		cancel:            cancel,
		subflows:          cfg.GetNormalizedSubflows(),
		chunkSize:         cfg.GetNormalizedChunkSize(),
		ackMaskBits:       cfg.GetNormalizedAckMaskBits(),
		maxInflight:       cfg.GetNormalizedMaxInflightBytes(),
		maxQueuePerFlow:   cfg.GetNormalizedMaxQueuePerFlow(),
		joinTimeout:       cfg.GetNormalizedJoinTimeout(),
		resumeTimeout:     cfg.GetNormalizedResumeTimeout(),
		reconnectSubflows: cfg.GetNormalizedReconnect(),
		psk:               cfg.GetNormalizedPsk(),
		role:              roleUnknown,
		createdAt:         now,
		flows:             make(map[byte]*subflow),
		sendNext:          0,
		lastAckAt:         now,
		sendWindow:        make(map[uint64]*sendSeg),
		txCh:              make(chan uint64, 1024),
		ackSignal:         make(chan struct{}, 1),
		flowSignal:        make(chan struct{}, 1),
		recvNext:          0,
		recvHold:          make(map[uint64][]byte),
		writeSignal:       make(chan struct{}, 1),
	}

	s.sackMaxBlocks = s.ackMaskBits / 128
	if s.sackMaxBlocks < 1 {
		s.sackMaxBlocks = 1
	}
	if s.sackMaxBlocks > 64 {
		s.sackMaxBlocks = 64
	}
	s.ackFrameCap = 1 + 8 + 1 + (16 * s.sackMaxBlocks)

	s.sendCond = sync.NewCond(&s.sendMu)
	s.rq = newReadQueue(s.freeRecvPayload)

	maxDataFrameCap := dataFrameHeaderLen + s.chunkSize
	s.sendFramePool.New = func() any {
		return make([]byte, 0, maxDataFrameCap)
	}
	s.recvPool.New = func() any {
		return make([]byte, 0, s.chunkSize)
	}
	s.ackFramePool.New = func() any {
		return make([]byte, 0, s.ackFrameCap)
	}

	// Randomize session ID and epoch by default (client side); server side may overwrite.
	_, _ = rand.Read(s.sessionID[:])
	var epochBytes [4]byte
	_, _ = rand.Read(epochBytes[:])
	s.epoch = binary.BigEndian.Uint32(epochBytes[:])

	go s.sendLoop()
	go s.retransmitLoop()
	go s.ackLoop()
	go s.writeFlushLoop()

	return s
}

func (s *session) maxSackBlocks() int { return s.sackMaxBlocks }

func (s *session) enqueueTX(dsn uint64) {
	if s.ctx.Err() != nil {
		return
	}
	select {
	case s.txCh <- dsn:
	case <-s.ctx.Done():
	}
}

func (s *session) beginDialing(id byte) bool {
	if id >= 32 {
		return true
	}
	b := uint32(1) << id
	for {
		old := s.dialingMask.Load()
		if old&b != 0 {
			return false
		}
		if s.dialingMask.CompareAndSwap(old, old|b) {
			return true
		}
	}
}

func (s *session) endDialing(id byte) {
	if id >= 32 {
		return
	}
	b := uint32(1) << id
	for {
		old := s.dialingMask.Load()
		if old&b == 0 {
			return
		}
		if s.dialingMask.CompareAndSwap(old, old&^b) {
			return
		}
	}
}

func (s *session) setOnClose(fn func()) { s.onClose = fn }

func (s *session) Read(p []byte) (int, error) { return s.rq.read(p) }

func (s *session) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.closing.Load() {
		return 0, io.ErrClosedPipe
	}
	if s.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}

	total := 0
	for len(p) > 0 {
		s.sendMu.Lock()
		if s.closing.Load() || s.ctx.Err() != nil {
			s.sendMu.Unlock()
			return total, io.ErrClosedPipe
		}

		if s.writeFrame == nil {
			s.writeFrame = s.allocSendFrame(dataFrameHeaderLen + s.chunkSize)
			// Defensive: sendFramePool may return a 0-len slice; ensure length
			// is enough for payload writes and header fill.
			if cap(s.writeFrame) >= dataFrameHeaderLen+s.chunkSize && len(s.writeFrame) < dataFrameHeaderLen+s.chunkSize {
				s.writeFrame = s.writeFrame[:dataFrameHeaderLen+s.chunkSize]
			}
			// Type byte is constant; the rest of the header is filled on flush.
			s.writeFrame[0] = frameTypeData
			s.writeOff = 0
		}

		room := s.chunkSize - s.writeOff
		if room <= 0 {
			dsn, ok, err := s.flushWriteLocked()
			s.sendMu.Unlock()
			if err != nil {
				return total, err
			}
			if ok {
				s.enqueueTX(dsn)
			}
			continue
		}

		n := room
		if n > len(p) {
			n = len(p)
		}
		copy(s.writeFrame[dataFrameHeaderLen+s.writeOff:], p[:n])
		s.writeOff += n
		total += n
		p = p[n:]

		if s.writeOff >= s.chunkSize {
			dsn, ok, err := s.flushWriteLocked()
			s.sendMu.Unlock()
			if err != nil {
				return total, err
			}
			if ok {
				s.enqueueTX(dsn)
			}
			continue
		}

		s.signalWriteFlushLocked()
		s.sendMu.Unlock()
	}
	return total, nil
}

func (s *session) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		return nil
	}

	if s.closing.Load() || s.ctx.Err() != nil {
		for i := range mb {
			if mb[i] != nil {
				mb[i].Release()
				mb[i] = nil
			}
		}
		return io.ErrClosedPipe
	}

	for i := range mb {
		b := mb[i]
		if b == nil {
			continue
		}
		p := b.Bytes()

		for len(p) > 0 {
			s.sendMu.Lock()
			if s.closing.Load() || s.ctx.Err() != nil {
				s.sendMu.Unlock()
				// Release current and remaining buffers.
				for j := i; j < len(mb); j++ {
					if mb[j] != nil {
						mb[j].Release()
						mb[j] = nil
					}
				}
				return io.ErrClosedPipe
			}

			if s.writeFrame == nil {
				s.writeFrame = s.allocSendFrame(dataFrameHeaderLen + s.chunkSize)
				// Defensive: sendFramePool may return a 0-len slice; ensure length.
				if cap(s.writeFrame) >= dataFrameHeaderLen+s.chunkSize && len(s.writeFrame) < dataFrameHeaderLen+s.chunkSize {
					s.writeFrame = s.writeFrame[:dataFrameHeaderLen+s.chunkSize]
				}
				s.writeFrame[0] = frameTypeData
				s.writeOff = 0
			}

			room := s.chunkSize - s.writeOff
			if room <= 0 {
				dsn, ok, err := s.flushWriteLocked()
				s.sendMu.Unlock()
				if err != nil {
					for j := i; j < len(mb); j++ {
						if mb[j] != nil {
							mb[j].Release()
							mb[j] = nil
						}
					}
					if ok {
						s.enqueueTX(dsn)
					}
					return err
				}
				if ok {
					s.enqueueTX(dsn)
				}
				continue
			}

			n := room
			if n > len(p) {
				n = len(p)
			}
			copy(s.writeFrame[dataFrameHeaderLen+s.writeOff:], p[:n])
			s.writeOff += n
			p = p[n:]

			if s.writeOff >= s.chunkSize {
				dsn, ok, err := s.flushWriteLocked()
				s.sendMu.Unlock()
				if err != nil {
					for j := i; j < len(mb); j++ {
						if mb[j] != nil {
							mb[j].Release()
							mb[j] = nil
						}
					}
					if ok {
						s.enqueueTX(dsn)
					}
					return err
				}
				if ok {
					s.enqueueTX(dsn)
				}
				continue
			}

			// Partial write: flush later with coalescing.
			s.signalWriteFlushLocked()
			s.sendMu.Unlock()
		}

		b.Release()
		mb[i] = nil
	}
	return nil
}

func (s *session) Close() error {
	if s.closing.Swap(true) {
		return nil
	}

	// Best effort: flush any pending partial frame so Close() does not drop the
	// tail chunk when caller finishes writing and immediately closes.
	var dsn uint64
	var ok bool
	s.sendMu.Lock()
	dsn, ok = s.flushWriteLockedForClose()
	s.sendMu.Unlock()
	if ok {
		s.enqueueTX(dsn)
	}

	// Best effort: wait briefly for queued data to be ACKed before tearing down
	// subflows. Use resumeTimeout as an upper bound so lossy/reordering paths
	// still have time to settle on close.
	maxDrainWait := s.resumeTimeout
	if maxDrainWait < 2*time.Second {
		maxDrainWait = 2 * time.Second
	}
	// If there is still outstanding in-flight data at close time, we are likely
	// in a graceful FIN path (application finished writing while transport is
	// still delivering queued data). Keep the session alive much longer so
	// retransmission/ACK can complete on high-delay links.
	s.sendMu.Lock()
	hasPendingInflight := s.inflightBytes > 0 || len(s.sendWindow) > 0
	s.sendMu.Unlock()
	if hasPendingInflight && maxDrainWait < 5*time.Minute {
		maxDrainWait = 5 * time.Minute
	}
	deadline := time.Now().Add(maxDrainWait)
	for {
		if s.ctx.Err() != nil {
			break
		}
		drained := false
		s.sendMu.Lock()
		drained = s.writeOff == 0 && len(s.sendWindow) == 0
		s.sendMu.Unlock()
		if drained {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	s.closeWithErrorReason(io.EOF, "close()")
	return nil
}

func (s *session) LocalAddr() net.Addr  { return s.localAddr }
func (s *session) RemoteAddr() net.Addr { return s.remoteAddr }
func (*session) TransportProtocol() string {
	return protocolName
}

func (*session) SetDeadline(time.Time) error      { return nil }
func (*session) SetReadDeadline(time.Time) error  { return nil }
func (*session) SetWriteDeadline(time.Time) error { return nil }

type sessionDiagState struct {
	sid   string
	epoch uint32
	role  sessionRole
	age   time.Duration

	localAddr  net.Addr
	remoteAddr net.Addr

	subflows int
	flows    int
	flowIDs  []byte

	chunkSize       int
	ackMaskBits     int
	maxSackBlocks   int
	maxInflight     int
	maxQueuePerFlow int
	joinTimeout     time.Duration
	resumeTimeout   time.Duration
	reconnect       bool

	sendNext      uint64
	inflightBytes int
	sendWindow    int
	lastDataAck   uint64
	lastAckAge    time.Duration

	recvNext   uint64
	recvHold   int
	recvHoldSz int
	reorderCap int

	ctxErr error
}

func (s *session) diagState() sessionDiagState {
	now := time.Now()
	st := sessionDiagState{
		sid:             hex.EncodeToString(s.sessionID[:]),
		epoch:           s.epoch,
		role:            s.role,
		age:             now.Sub(s.createdAt),
		subflows:        s.subflows,
		chunkSize:       s.chunkSize,
		ackMaskBits:     s.ackMaskBits,
		maxSackBlocks:   s.sackMaxBlocks,
		maxInflight:     s.maxInflight,
		maxQueuePerFlow: s.maxQueuePerFlow,
		joinTimeout:     s.joinTimeout,
		resumeTimeout:   s.resumeTimeout,
		reconnect:       s.reconnectSubflows,
		reorderCap:      s.maxInflight * 2,
		ctxErr:          s.ctx.Err(),
	}

	s.flowsMu.RLock()
	st.localAddr = s.localAddr
	st.remoteAddr = s.remoteAddr
	st.flows = len(s.flows)
	if st.flows > 0 {
		st.flowIDs = make([]byte, 0, st.flows)
		for id := range s.flows {
			st.flowIDs = append(st.flowIDs, id)
		}
	}
	s.flowsMu.RUnlock()
	if len(st.flowIDs) > 1 {
		sort.Slice(st.flowIDs, func(i, j int) bool { return st.flowIDs[i] < st.flowIDs[j] })
	}

	s.sendMu.Lock()
	st.sendNext = s.sendNext
	st.inflightBytes = s.inflightBytes
	st.sendWindow = len(s.sendWindow)
	st.lastDataAck = s.lastDataAck
	st.lastAckAge = now.Sub(s.lastAckAt)
	s.sendMu.Unlock()

	s.recvMu.Lock()
	st.recvNext = s.recvNext
	st.recvHold = len(s.recvHold)
	st.recvHoldSz = s.recvHoldSz
	s.recvMu.Unlock()

	return st
}

func (s *session) closeWithError(err error) { s.closeWithErrorReason(err, "") }

func (s *session) closeWithErrorReason(err error, reason string) {
	s.closeOnce.Do(func() {
		st := s.diagState()
		errors.LogDebug(s.ctx,
			"axpath: session closing: sid=", st.sid,
			" epoch=", st.epoch,
			" role=", st.role,
			" reason=", reason,
			" err=", err,
			" ctx_err=", st.ctxErr,
			" age=", st.age,
			" session_local=", st.localAddr,
			" session_remote=", st.remoteAddr,
			" flows=", st.flows, "/", st.subflows,
			" flow_ids=", st.flowIDs,
			" chunk_size=", st.chunkSize,
			" sack_cap_bits=", st.ackMaskBits,
			" sack_max_blocks=", st.maxSackBlocks,
			" max_inflight_bytes=", st.maxInflight,
			" inflight_bytes=", st.inflightBytes,
			" send_window=", st.sendWindow,
			" send_next_dsn=", st.sendNext,
			" last_data_ack=", st.lastDataAck,
			" last_ack_age=", st.lastAckAge,
			" recv_next_dsn=", st.recvNext,
			" recv_hold=", st.recvHold,
			" recv_hold_bytes=", st.recvHoldSz, "/", st.reorderCap,
			" join_timeout=", st.joinTimeout,
			" resume_timeout=", st.resumeTimeout,
			" reconnect=", st.reconnect,
		)

		s.cancel()

		var cb func()
		cb = s.onClose

		// Close flows outside of flowsMu to avoid lock-order surprises.
		var flows []*subflow
		s.flowsMu.Lock()
		for _, f := range s.flows {
			if f != nil {
				flows = append(flows, f)
			}
		}
		s.flows = make(map[byte]*subflow)
		s.flowsMu.Unlock()
		for _, f := range flows {
			f.close()
		}

		if s.rq != nil {
			s.rq.close(err)
		}

		s.sendMu.Lock()
		if s.writeFrame != nil {
			s.freeSendFrame(s.writeFrame)
			s.writeFrame = nil
		}
		s.writeOff = 0

		s.inflightBytes = 0
		for dsn, seg := range s.sendWindow {
			if seg == nil {
				delete(s.sendWindow, dsn)
				continue
			}
			seg.acked = true
			if seg.inflight <= 0 {
				s.freeSendFrame(seg.frame)
				delete(s.sendWindow, dsn)
			}
		}
		s.sendCond.Broadcast()
		s.sendMu.Unlock()

		// Release out-of-order receive buffers on close to avoid retaining large
		// amounts of memory until GC. (readQueue.close() only releases in-order
		// data already pushed to the queue.)
		s.recvMu.Lock()
		for dsn, b := range s.recvHold {
			if b != nil {
				s.freeRecvPayload(b)
			}
			delete(s.recvHold, dsn)
		}
		s.recvHoldSz = 0
		s.recvMu.Unlock()

		if cb != nil {
			cb()
		}
	})
}

func (s *session) attachSubflow(id byte, conn net.Conn) error {
	if conn == nil {
		return errors.New("axpath: nil conn")
	}
	if s.ctx.Err() != nil {
		return io.ErrClosedPipe
	}

	f := newSubflow(id, conn, s.maxQueuePerFlow)
	sfLocal := conn.LocalAddr()
	sfRemote := conn.RemoteAddr()

	replaced := false
	var gen uint64
	s.flowsMu.Lock()
	if old := s.flows[id]; old != nil {
		replaced = true
		old.close()
	}
	s.flows[id] = f
	if s.localAddr == nil {
		s.localAddr = sfLocal
	}
	if s.remoteAddr == nil {
		s.remoteAddr = sfRemote
	}
	gen = s.emptyGen.Add(1)
	s.flowsMu.Unlock()

	st := s.diagState()
	errors.LogDebug(s.ctx,
		"axpath: subflow attached: sid=", st.sid,
		" epoch=", st.epoch,
		" role=", st.role,
		" id=", id,
		" replaced=", replaced,
		" gen=", gen,
		" subflow_local=", sfLocal,
		" subflow_remote=", sfRemote,
		" session_local=", st.localAddr,
		" session_remote=", st.remoteAddr,
		" flows=", st.flows, "/", st.subflows,
		" flow_ids=", st.flowIDs,
	)

	f.start(s)
	// Ensure the peer eventually sees a fresh ACK after subflow (re)attachment.
	s.signalAck()
	s.signalFlow()
	return nil
}

func (s *session) removeSubflow(f *subflow) (removed bool, nowEmpty bool) {
	if f == nil {
		return false, false
	}
	s.flowsMu.Lock()
	defer s.flowsMu.Unlock()

	// Only remove the flow instance that triggered the error. A newer subflow may
	// have already replaced this ID (resume/reconnect), and we must not close it.
	if cur := s.flows[f.id]; cur == f {
		delete(s.flows, f.id)
		removed = true
	}
	return removed, len(s.flows) == 0
}

func (s *session) pickSubflow() *subflow {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	var best *subflow
	bestQLen := int(^uint(0) >> 1)
	for _, f := range s.flows {
		if f == nil || f.isClosed() {
			continue
		}
		ql := len(f.dataCh) + len(f.ctlCh)
		if ql < bestQLen {
			bestQLen = ql
			best = f
		}
	}
	return best
}

func (s *session) pickDataSubflow() *subflow {
	s.flowsMu.RLock()
	defer s.flowsMu.RUnlock()
	var best *subflow
	bestQLen := int(^uint(0) >> 1)
	for _, f := range s.flows {
		if f == nil || f.isClosed() {
			continue
		}
		ql := len(f.dataCh)
		if ql < bestQLen {
			bestQLen = ql
			best = f
		}
	}
	return best
}

func (s *session) safeQueueControlToFlow(f *subflow, frame []byte) (ok bool) {
	if f == nil || f.isClosed() {
		return false
	}
	select {
	case <-f.done:
		return false
	default:
	}
	select {
	case f.ctlCh <- frame:
		return true
	case <-f.done:
		return false
	case <-s.ctx.Done():
		return false
	}
}

func (s *session) safeQueueDataToFlow(f *subflow, frame []byte) (ok bool) {
	if f == nil || f.isClosed() {
		return false
	}
	select {
	case <-f.done:
		return false
	default:
	}
	select {
	case f.dataCh <- frame:
		return true
	case <-f.done:
		return false
	case <-s.ctx.Done():
		return false
	}
}

func (s *session) sendControl(b []byte) {
	// Control frames (especially ACK) must not be silently dropped; otherwise the
	// sender may stall at maxInflight and no new data will arrive to trigger more
	// ACK signals.
	for {
		f := s.pickSubflow()
		if f == nil {
			if len(b) > 0 && b[0] == frameTypeAck {
				s.freeAckFrame(b)
			}
			return
		}
		if s.safeQueueControlToFlow(f, b) {
			return
		}
		if s.ctx.Err() != nil {
			if len(b) > 0 && b[0] == frameTypeAck {
				s.freeAckFrame(b)
			}
			return
		}
	}
}

func (s *session) onSubflowError(f *subflow, op string, err error) {
	if f == nil {
		return
	}
	if f.dead.Swap(true) {
		return
	}

	var sfLocal, sfRemote net.Addr
	if f.conn != nil {
		sfLocal = f.conn.LocalAddr()
		sfRemote = f.conn.RemoteAddr()
	}

	f.close()

	// Requeue segments that were last sent on this flow.
	var resend []uint64
	s.sendMu.Lock()
	for dsn, seg := range s.sendWindow {
		if seg != nil && !seg.acked && seg.sent && seg.lastFlow == f.id {
			resend = append(resend, dsn)
		}
	}
	s.sendMu.Unlock()
	for _, dsn := range resend {
		s.enqueueTX(dsn)
	}

	removed, nowEmpty := s.removeSubflow(f)
	st := s.diagState()

	if err != nil {
		// EOF/close/cancel are common during teardown and should not spam Info logs.
		commonClose := goerrors.Is(err, io.EOF) ||
			goerrors.Is(err, io.ErrClosedPipe) ||
			goerrors.Is(err, context.Canceled) ||
			goerrors.Is(err, net.ErrClosed)

		// Connection resets / broken pipes are also common when the peer closes
		// aggressively (e.g. application teardown, unread buffered data). Keep the
		// state snapshot in Debug, but avoid spamming Info unless we were actively
		// sending.
		// On Windows, common reset errors are WSAECONNRESET (10054) / WSAECONNABORTED
		// (10053). We avoid importing windows-only constants here by matching the
		// errno numbers directly.
		isResetLike := goerrors.Is(err, syscall.ECONNRESET) ||
			goerrors.Is(err, syscall.EPIPE) ||
			goerrors.Is(err, syscall.ECONNABORTED) ||
			goerrors.Is(err, syscall.Errno(10054)) ||
			goerrors.Is(err, syscall.Errno(10053))
		if isResetLike && (s.ctx.Err() != nil || nowEmpty || (st.inflightBytes == 0 && st.sendWindow == 0)) {
			commonClose = true
		}

		prefix := "axpath: subflow error: sid="
		if commonClose {
			prefix = "axpath: subflow closed: sid="
		}
		errors.LogDebug(s.ctx,
			prefix, st.sid,
			" epoch=", st.epoch,
			" role=", st.role,
			" flow=", f.id,
			" op=", op,
			" err=", err,
			" stale=", !removed,
			" now_empty=", nowEmpty,
			" resend=", len(resend),
			" subflow_local=", sfLocal,
			" subflow_remote=", sfRemote,
			" session_local=", st.localAddr,
			" session_remote=", st.remoteAddr,
			" flows=", st.flows, "/", st.subflows,
			" flow_ids=", st.flowIDs,
			" inflight_bytes=", st.inflightBytes, "/", st.maxInflight,
			" send_window=", st.sendWindow,
			" last_data_ack=", st.lastDataAck,
			" last_ack_age=", st.lastAckAge,
			" recv_next_dsn=", st.recvNext,
			" recv_hold=", st.recvHold,
			" recv_hold_bytes=", st.recvHoldSz, "/", st.reorderCap,
		)

		if !commonClose {
			errors.LogInfo(s.ctx, "axpath: subflow ", f.id, " ", op, " error: ", err.Error())
		}
	} else {
		errors.LogDebug(s.ctx,
			"axpath: subflow closed: sid=", st.sid,
			" epoch=", st.epoch,
			" role=", st.role,
			" flow=", f.id,
			" op=", op,
			" stale=", !removed,
			" now_empty=", nowEmpty,
			" resend=", len(resend),
			" subflow_local=", sfLocal,
			" subflow_remote=", sfRemote,
			" session_local=", st.localAddr,
			" session_remote=", st.remoteAddr,
			" flows=", st.flows, "/", st.subflows,
			" flow_ids=", st.flowIDs,
		)
	}

	if nowEmpty {
		sid := st.sid
		epoch := st.epoch
		role := st.role

		gen := s.emptyGen.Add(1)
		if s.resumeTimeout > 0 {
			errors.LogDebug(s.ctx,
				"axpath: session has no subflows; scheduling close after resume_timeout=", s.resumeTimeout,
				" sid=", sid,
				" epoch=", epoch,
				" role=", role,
				" gen=", gen,
			)
			go func(gen uint64) {
				timer := time.NewTimer(s.resumeTimeout)
				defer timer.Stop()
				select {
				case <-timer.C:
					if s.emptyGen.Load() == gen {
						s.closeWithErrorReason(io.EOF, "resume_timeout_no_subflows")
						return
					}
				case <-s.ctx.Done():
				}
			}(gen)
		} else {
			closeErr := err
			if closeErr == nil {
				closeErr = io.EOF
			}
			s.closeWithErrorReason(closeErr, "no_subflows")
		}
	}
}

func (s *session) allocSendFrame(n int) []byte {
	if n <= 0 {
		return nil
	}
	v := s.sendFramePool.Get()
	if v == nil {
		return make([]byte, n)
	}
	b := v.([]byte)
	if cap(b) < n {
		return make([]byte, n)
	}
	return b[:n]
}

func (s *session) freeSendFrame(b []byte) {
	if b == nil {
		return
	}
	maxCap := dataFrameHeaderLen + s.chunkSize
	if cap(b) != maxCap {
		return
	}
	s.sendFramePool.Put(b[:0])
}

func (s *session) allocAckFrame() []byte {
	v := s.ackFramePool.Get()
	if v == nil {
		return make([]byte, 0, s.ackFrameCap)
	}
	b := v.([]byte)
	if cap(b) != s.ackFrameCap {
		return make([]byte, 0, s.ackFrameCap)
	}
	return b[:0]
}

func (s *session) freeAckFrame(b []byte) {
	if b == nil {
		return
	}
	if cap(b) != s.ackFrameCap {
		return
	}
	s.ackFramePool.Put(b[:0])
}

func (s *session) allocRecvPayload(n int) []byte {
	if n <= 0 {
		return nil
	}
	if n > s.chunkSize {
		return make([]byte, n)
	}
	v := s.recvPool.Get()
	if v == nil {
		return make([]byte, n)
	}
	b := v.([]byte)
	if cap(b) < n {
		return make([]byte, n)
	}
	return b[:n]
}

func (s *session) freeRecvPayload(b []byte) {
	if b == nil {
		return
	}
	if cap(b) != s.chunkSize {
		return
	}
	s.recvPool.Put(b[:0])
}

func (s *session) flushWriteLocked() (dsn uint64, ok bool, err error) {
	if s.writeFrame == nil || s.writeOff <= 0 {
		return 0, false, nil
	}
	if s.writeOff > s.chunkSize {
		return 0, false, errors.New("axpath: internal: writeOff > chunkSize")
	}

	payloadLen := s.writeOff

	startWait := time.Time{}
	warned := false
	for s.inflightBytes+payloadLen > s.maxInflight {
		if s.ctx.Err() != nil {
			return 0, false, io.ErrClosedPipe
		}
		if startWait.IsZero() {
			startWait = time.Now()
		} else if !warned && time.Since(startWait) > 2*time.Second {
			errors.LogDebug(s.ctx,
				"axpath: send window full: inflight_bytes=", s.inflightBytes,
				" max_inflight_bytes=", s.maxInflight,
				" send_window=", len(s.sendWindow),
				" last_data_ack=", s.lastDataAck,
				" last_ack_age=", time.Since(s.lastAckAt),
			)
			warned = true
		}
		s.sendCond.Wait()
	}

	dsn = s.sendNext
	s.sendNext += uint64(payloadLen)

	frame := s.writeFrame
	need := dataFrameHeaderLen + payloadLen
	// Defensive: under some edge cases (pool misuse / corruption), writeFrame can
	// be non-nil but 0-len. Ensure it is long enough before indexing/slicing.
	if len(frame) < need {
		if cap(frame) < need {
			// Should never happen. Allocate a new frame to avoid crashing.
			frame = s.allocSendFrame(need)
		} else {
			frame = frame[:need]
		}
		s.writeFrame = frame
	}
	frame[0] = frameTypeData
	frame[1] = 0 // flags
	binary.BigEndian.PutUint64(frame[2:10], dsn)
	binary.BigEndian.PutUint32(frame[10:14], uint32(payloadLen))
	frame = frame[:need]

	s.sendWindow[dsn] = &sendSeg{
		frame:      frame,
		payloadLen: payloadLen,
	}
	s.inflightBytes += payloadLen

	s.writeFrame = nil
	s.writeOff = 0

	return dsn, true, nil
}

func (s *session) flushWriteLockedForClose() (dsn uint64, ok bool) {
	if s.writeFrame == nil || s.writeOff <= 0 {
		return 0, false
	}
	if s.writeOff > s.chunkSize {
		return 0, false
	}

	payloadLen := s.writeOff
	dsn = s.sendNext
	s.sendNext += uint64(payloadLen)

	frame := s.writeFrame
	need := dataFrameHeaderLen + payloadLen
	if len(frame) < need {
		if cap(frame) < need {
			frame = s.allocSendFrame(need)
		} else {
			frame = frame[:need]
		}
		s.writeFrame = frame
	}
	frame[0] = frameTypeData
	frame[1] = 0
	binary.BigEndian.PutUint64(frame[2:10], dsn)
	binary.BigEndian.PutUint32(frame[10:14], uint32(payloadLen))
	frame = frame[:need]

	s.sendWindow[dsn] = &sendSeg{
		frame:      frame,
		payloadLen: payloadLen,
	}
	s.inflightBytes += payloadLen
	s.writeFrame = nil
	s.writeOff = 0

	return dsn, true
}

func (s *session) signalWriteFlushLocked() {
	select {
	case s.writeSignal <- struct{}{}:
	default:
	}
}

func (s *session) writeFlushLoop() {
	const coalesceDelay = 1 * time.Millisecond
	timer := time.NewTimer(time.Hour)
	timer.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.writeSignal:
		}

		timer.Reset(coalesceDelay)
		for {
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-s.writeSignal:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(coalesceDelay)
			case <-timer.C:
				s.sendMu.Lock()
				// Ignore flush errors here; Write() will surface them for active writers.
				dsn, ok, _ := s.flushWriteLocked()
				s.sendMu.Unlock()
				if ok {
					s.enqueueTX(dsn)
				}
				goto NEXT
			}
		}

	NEXT:
	}
}

func (s *session) sendLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case dsn := <-s.txCh:
			s.sendDSN(dsn)
		}
	}
}

func (s *session) sendDSN(dsn uint64) {
	// Never drop DSNs just because no subflow is attached yet. This can happen
	// during mux bursts at session start. Dropping causes massive reordering
	// (recv_next_dsn stays at 0 while high DSNs arrive) and reorder buffer
	// overflows on the receiver.
	var f *subflow
	for {
		f = s.pickDataSubflow()
		if f != nil {
			break
		}
		select {
		case <-s.ctx.Done():
			return
		case <-s.flowSignal:
		}
	}

	s.sendMu.Lock()
	seg, ok := s.sendWindow[dsn]
	if !ok || seg == nil || seg.acked {
		s.sendMu.Unlock()
		return
	}

	seg.sent = true
	seg.lastSent = time.Now()
	seg.lastFlow = f.id
	seg.inflight++
	frame := seg.frame
	s.sendMu.Unlock()

	queued := s.safeQueueDataToFlow(f, frame)
	if !queued {
		// Roll back inflight ref and retry later.
		s.onDataFrameDone(dsn)
		s.enqueueTX(dsn)
	}
}

func (s *session) onDataFrameDone(dsn uint64) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	seg, ok := s.sendWindow[dsn]
	if !ok || seg == nil {
		return
	}
	if seg.inflight > 0 {
		seg.inflight--
	}
	if seg.acked && seg.inflight <= 0 {
		s.freeSendFrame(seg.frame)
		delete(s.sendWindow, dsn)
	}
}

func (s *session) onData(dsn uint64, payload []byte) {
	if len(payload) == 0 {
		s.freeRecvPayload(payload)
		s.signalAck()
		return
	}

	s.recvMu.Lock()

	if dsn < s.recvNext {
		// Duplicate.
		s.recvMu.Unlock()
		s.freeRecvPayload(payload)
		s.signalAck()
		return
	}

	if dsn == s.recvNext {
		if err := s.rq.push(payload); err != nil {
			s.recvMu.Unlock()
			s.freeRecvPayload(payload)
			return
		}
		s.recvNext += uint64(len(payload))
		for {
			b, ok := s.recvHold[s.recvNext]
			if !ok {
				break
			}
			delete(s.recvHold, s.recvNext)
			s.recvHoldSz -= len(b)
			if err := s.rq.push(b); err != nil {
				s.recvMu.Unlock()
				s.freeRecvPayload(b)
				s.closeWithErrorReason(err, "readqueue_push")
				return
			}
			s.recvNext += uint64(len(b))
		}
		s.recvMu.Unlock()
		s.signalAck()
		return
	}

	// Out-of-order.
	if _, ok := s.recvHold[dsn]; ok {
		s.recvMu.Unlock()
		s.freeRecvPayload(payload)
		s.signalAck()
		return
	}

	// Hard cap for out-of-order buffering.
	if s.recvHoldSz+len(payload) > s.maxInflight*2 {
		holdSz := s.recvHoldSz
		capSz := s.maxInflight * 2
		recvNext := s.recvNext
		s.recvMu.Unlock()
		s.freeRecvPayload(payload)
		// Do not hard-close the entire session on reordering bursts; instead,
		// drop excess out-of-order frames to apply backpressure and rely on
		// retransmission for eventual correctness.
		errors.LogInfo(s.ctx, "axpath: reorder buffer overflow: dropping out-of-order frame: recv_hold_bytes=", holdSz, " cap_bytes=", capSz, " dsn=", dsn, " recv_next_dsn=", recvNext)
		s.signalAck()
		return
	}

	s.recvHold[dsn] = payload
	s.recvHoldSz += len(payload)
	s.recvMu.Unlock()
	s.signalAck()
}

func (s *session) signalAck() {
	select {
	case s.ackSignal <- struct{}{}:
	default:
	}
}

func (s *session) signalAckLocked() { s.signalAck() }

func (s *session) signalFlow() {
	select {
	case s.flowSignal <- struct{}{}:
	default:
	}
}

func (s *session) buildSACKBlocksLocked(dataAck uint64) []sackBlock {
	if len(s.recvHold) == 0 {
		return nil
	}

	keys := make([]uint64, 0, len(s.recvHold))
	for k := range s.recvHold {
		if k < dataAck {
			// Should not happen, but ignore.
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	maxBlocks := s.sackMaxBlocks
	blocks := make([]sackBlock, 0, maxBlocks)

	var cur sackBlock
	cur.Start = keys[0]
	cur.End = cur.Start + uint64(len(s.recvHold[cur.Start]))
	for _, start := range keys[1:] {
		b := s.recvHold[start]
		end := start + uint64(len(b))
		if start <= cur.End {
			// Overlap (duplicate/reinject) or adjacent: merge.
			if end > cur.End {
				cur.End = end
			}
			continue
		}
		blocks = append(blocks, cur)
		if len(blocks) >= maxBlocks {
			return blocks
		}
		cur = sackBlock{Start: start, End: end}
	}
	blocks = append(blocks, cur)
	if len(blocks) > maxBlocks {
		blocks = blocks[:maxBlocks]
	}
	return blocks
}

func (s *session) ackLoop() {
	coalesce := 5 * time.Millisecond
	// Periodically resend ACK state to avoid "maxInflight deadlock" if the last ACK
	// was lost and the sender stopped sending new data (so no new onData() events
	// happen to trigger signalAck()).
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.ackSignal:
		case <-ticker.C:
			s.recvMu.Lock()
			need := s.recvNext > 0 || len(s.recvHold) > 0
			s.recvMu.Unlock()
			if !need {
				continue
			}
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(coalesce)
		for {
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-s.ackSignal:
			case <-ticker.C:
			case <-timer.C:
				goto SEND
			}
		}

	SEND:
		var dataAck uint64
		var blocks []sackBlock
		s.recvMu.Lock()
		dataAck = s.recvNext
		blocks = s.buildSACKBlocksLocked(dataAck)
		s.recvMu.Unlock()

		buf := s.allocAckFrame()
		b := encodeAckFrameInto(buf, dataAck, blocks)
		s.sendControl(b)
	}
}

func normalizeSACKBlocks(dataAck uint64, in []sackBlock) []sackBlock {
	if len(in) == 0 {
		return nil
	}
	blocks := in[:0]
	for _, b := range in {
		if b.End <= b.Start {
			continue
		}
		if b.End <= dataAck {
			continue
		}
		if b.Start < dataAck {
			b.Start = dataAck
		}
		blocks = append(blocks, b)
	}
	if len(blocks) == 0 {
		return nil
	}
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].Start == blocks[j].Start {
			return blocks[i].End < blocks[j].End
		}
		return blocks[i].Start < blocks[j].Start
	})
	out := blocks[:0]
	cur := blocks[0]
	for _, b := range blocks[1:] {
		if b.Start <= cur.End {
			if b.End > cur.End {
				cur.End = b.End
			}
			continue
		}
		out = append(out, cur)
		cur = b
	}
	out = append(out, cur)
	return out
}

func (s *session) onAck(dataAck uint64, sacks []sackBlock) {
	var fastResend []uint64

	s.sendMu.Lock()
	now := time.Now()
	s.lastDataAck = dataAck
	s.lastAckAt = now

	blocks := normalizeSACKBlocks(dataAck, sacks)

	ackedRange := func(start, end uint64) bool {
		if end <= dataAck {
			return true
		}
		for _, b := range blocks {
			if start >= b.Start && end <= b.End {
				return true
			}
		}
		return false
	}

	highest := dataAck
	for _, b := range blocks {
		if b.End > highest {
			highest = b.End
		}
	}

	const maxFastResend = 64
	for dsn, seg := range s.sendWindow {
		if seg == nil {
			delete(s.sendWindow, dsn)
			continue
		}

		start := dsn
		end := dsn + uint64(seg.payloadLen)

		if !seg.acked && ackedRange(start, end) {
			seg.acked = true
			s.inflightBytes -= seg.payloadLen
			if seg.inflight <= 0 {
				s.freeSendFrame(seg.frame)
				delete(s.sendWindow, dsn)
			}
			continue
		}

		// Fast retransmit for holes implied by SACK beyond dataAck.
		if len(blocks) == 0 || len(fastResend) >= maxFastResend {
			continue
		}
		if start < dataAck || end > highest {
			continue
		}
		if ackedRange(start, end) {
			continue
		}
		if !seg.sent {
			fastResend = append(fastResend, dsn)
			continue
		}
		if now.Sub(seg.lastSent) < 50*time.Millisecond {
			continue
		}
		fastResend = append(fastResend, dsn)
	}

	s.sendCond.Broadcast()
	s.sendMu.Unlock()

	for _, dsn := range fastResend {
		s.enqueueTX(dsn)
	}
}

func (s *session) retransmitLoop() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}

		now := time.Now()
		var todo []uint64

		s.sendMu.Lock()
		for dsn, seg := range s.sendWindow {
			if seg == nil {
				continue
			}
			if seg.acked {
				continue
			}
			if !seg.sent {
				todo = append(todo, dsn)
				continue
			}
			if now.Sub(seg.lastSent) > 800*time.Millisecond {
				todo = append(todo, dsn)
			}
		}
		s.sendMu.Unlock()

		for _, dsn := range todo {
			s.enqueueTX(dsn)
		}
	}
}

func writeAll(w net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
