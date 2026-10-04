package axpath

import (
	"errors"
	"io"
	"sync"
)

type readQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	closed bool
	err    error

	release func([]byte)

	q       [][]byte
	head    []byte
	headOff int
}

func newReadQueue(release func([]byte)) *readQueue {
	rq := &readQueue{release: release}
	rq.cond = sync.NewCond(&rq.mu)
	return rq
}

func (q *readQueue) push(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		if q.err != nil {
			return q.err
		}
		return io.ErrClosedPipe
	}
	q.q = append(q.q, b)
	q.cond.Signal()
	return nil
}

func (q *readQueue) close(err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	q.err = err

	// Release buffered data to avoid holding large pooled buffers after close.
	if q.release != nil {
		if q.head != nil {
			q.release(q.head)
			q.head = nil
			q.headOff = 0
		}
		for _, b := range q.q {
			q.release(b)
		}
	}
	q.q = nil

	q.cond.Broadcast()
}

func (q *readQueue) read(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for {
		if len(p) == 0 {
			return 0, nil
		}

		if q.head != nil {
			n := copy(p, q.head[q.headOff:])
			q.headOff += n
			if q.headOff >= len(q.head) {
				if q.release != nil {
					q.release(q.head)
				}
				q.head = nil
				q.headOff = 0
			}
			return n, nil
		}

		if len(q.q) > 0 {
			// Avoid loitering: clear the popped element so large payload buffers
			// can be reclaimed/dropped from sync.Pool on GC pressure.
			q.head = q.q[0]
			q.q[0] = nil
			q.q = q.q[1:]
			if len(q.q) == 0 {
				q.q = nil
			}
			continue
		}

		if q.closed {
			if q.err != nil && !errors.Is(q.err, io.EOF) {
				return 0, q.err
			}
			return 0, io.EOF
		}

		q.cond.Wait()
	}
}
