package axpath

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/ImAubrey/acore/common/errors"
)

type subflow struct {
	id   byte
	conn net.Conn

	ctlCh  chan []byte
	dataCh chan []byte
	done   chan struct{}

	closed atomic.Bool
	dead   atomic.Bool // ensures onSubflowError runs once
}

func newSubflow(id byte, conn net.Conn, maxQueue int) *subflow {
	if maxQueue < 1 {
		maxQueue = 1
	}
	ctlCap := maxQueue
	if ctlCap < 4 {
		ctlCap = 4
	}
	return &subflow{
		id:     id,
		conn:   conn,
		ctlCh:  make(chan []byte, ctlCap),
		dataCh: make(chan []byte, maxQueue),
		done:   make(chan struct{}),
	}
}

func (f *subflow) close() {
	if f.closed.Swap(true) {
		return
	}
	_ = f.conn.Close()
	close(f.done)
}

func (f *subflow) isClosed() bool { return f.closed.Load() }

func (f *subflow) start(s *session) {
	go f.writeLoop(s)
	go f.readLoop(s)
}

func (f *subflow) writeLoop(s *session) {
	draining := false
	nextWriteDeadlineUpdate := time.Time{}
	for {
		select {
		case <-f.done:
			return
		default:
		}

		// Prefer control frames.
		select {
		case <-f.done:
			return
		case b := <-f.ctlCh:
			f.writeOne(s, b, &draining, &nextWriteDeadlineUpdate)
			continue
		default:
		}

		// No pending control frame; block on either control/data.
		select {
		case <-f.done:
			return
		case b := <-f.ctlCh:
			f.writeOne(s, b, &draining, &nextWriteDeadlineUpdate)
		case b := <-f.dataCh:
			f.writeOne(s, b, &draining, &nextWriteDeadlineUpdate)
		}
	}
}

func (f *subflow) writeOne(s *session, b []byte, draining *bool, nextDeadlineUpdate *time.Time) {
	if len(b) == 0 {
		return
	}

	typ := b[0]
	dsn, isData := parseDataDSN(b)

	var err error
	if !*draining {
		// Updating deadlines per-frame is a syscall-heavy fast path. We only
		// extend the deadline periodically while the flow is active.
		now := time.Now()
		if nextDeadlineUpdate == nil || nextDeadlineUpdate.IsZero() || now.After(*nextDeadlineUpdate) {
			_ = f.conn.SetWriteDeadline(now.Add(30 * time.Second))
			if nextDeadlineUpdate != nil {
				*nextDeadlineUpdate = now.Add(10 * time.Second)
			}
		}
		err = writeAll(f.conn, b)
	}

	if isData {
		s.onDataFrameDone(dsn)
	} else if typ == frameTypeAck {
		// ACK frames are allocated independently (not tied to sendWindow) and can
		// be safely recycled once written (or drained on error).
		s.freeAckFrame(b)
	}

	if err != nil && !*draining {
		// onSubflowError will close the flow (including channels), so we can drain
		// buffered items and release inflight refs without writing them.
		*draining = true
		s.onSubflowError(f, "write", err)
	}
}

func parseDataDSN(b []byte) (dsn uint64, ok bool) {
	if len(b) < dataFrameHeaderLen {
		return 0, false
	}
	if b[0] != frameTypeData {
		return 0, false
	}
	// type(1) flags(1) dsn(8) len(4)
	return binary.BigEndian.Uint64(b[2:10]), true
}

func (f *subflow) readLoop(s *session) {
	maxSack := s.maxSackBlocks()
	sackScratch := make([]sackBlock, 0, maxSack)
	// Buffered reads drastically reduce syscall overhead for small header reads
	// (type/hdr/ack blocks), improving throughput especially on single-subflow
	// sessions.
	br := bufio.NewReaderSize(f.conn, 64*1024)
	nextReadDeadlineUpdate := time.Time{}

	for {
		var typ [1]byte
		// Same idea as write deadlines: avoid calling SetReadDeadline on every
		// frame (syscall-heavy), while still keeping a bounded read timeout.
		now := time.Now()
		if nextReadDeadlineUpdate.IsZero() || now.After(nextReadDeadlineUpdate) {
			_ = f.conn.SetReadDeadline(now.Add(5 * time.Minute))
			nextReadDeadlineUpdate = now.Add(30 * time.Second)
		}
		_, err := io.ReadFull(br, typ[:])
		if err != nil {
			s.onSubflowError(f, "read", err)
			return
		}

		switch typ[0] {
		case frameTypeData:
			var hdr [13]byte
			if _, err := io.ReadFull(br, hdr[:]); err != nil {
				s.onSubflowError(f, "read", err)
				return
			}
			// hdr: flags(1) dsn(8) len(4)
			dsn := binary.BigEndian.Uint64(hdr[1:9])
			n := int(binary.BigEndian.Uint32(hdr[9:13]))
			if n < 0 || n > s.chunkSize {
				s.onSubflowError(f, "read", errors.New("axpath: invalid data length"))
				return
			}
			payload := s.allocRecvPayload(n)
			if n > 0 {
				if _, err := io.ReadFull(br, payload[:n]); err != nil {
					s.freeRecvPayload(payload)
					s.onSubflowError(f, "read", err)
					return
				}
			}
			s.onData(dsn, payload[:n])
		case frameTypeAck:
			dataAck, blocks, err := readAckFrameInto(br, maxSack, sackScratch[:0])
			if err != nil {
				s.onSubflowError(f, "read", err)
				return
			}
			s.onAck(dataAck, blocks)
			sackScratch = blocks[:0]
		case frameTypePing:
			// Drain 8 bytes, respond with PONG.
			var v [8]byte
			if _, err := io.ReadFull(br, v[:]); err != nil {
				s.onSubflowError(f, "read", err)
				return
			}
			resp := make([]byte, 1+8)
			resp[0] = frameTypePong
			copy(resp[1:], v[:])
			s.sendControl(resp)
		case frameTypePong:
			// Drain 8 bytes.
			var v [8]byte
			if _, err := io.ReadFull(br, v[:]); err != nil {
				s.onSubflowError(f, "read", err)
				return
			}
		default:
			errors.LogInfo(s.ctx, "axpath: unknown frame type ", typ[0])
			s.onSubflowError(f, "read", errors.New("unknown frame type"))
			return
		}
	}
}
