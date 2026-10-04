package dispatcher

import (
	"sync"
	"time"

	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/transport/pipe"
)

type cachedReader struct {
	sync.Mutex
	reader buf.TimeoutReader // *pipe.Reader or *buf.TimeoutWrapperReader
	cache  buf.MultiBuffer
}

func (r *cachedReader) Cache(b *buf.Buffer, deadline time.Duration) error {
	mb, err := r.reader.ReadMultiBufferTimeout(deadline)
	// pipe.Reader returns buf.ErrReadTimeout on timeout. For sniffing, treat it as
	// "no new bytes yet" and let the caller's overall budget decide.
	if err != nil && err != buf.ErrReadTimeout {
		return err
	}
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	rawBytes := b.Extend(min(r.cache.Len(), b.Cap()))
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
	return nil
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBufferTimeout(timeout)
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	if p, ok := r.reader.(*pipe.Reader); ok {
		p.Interrupt()
	}
}

// ReadCachedMultiBuffer returns cached data without touching the underlying reader.
func (r *cachedReader) ReadCachedMultiBuffer() (buf.MultiBuffer, bool) {
	r.Lock()
	defer r.Unlock()
	if r.cache == nil || r.cache.IsEmpty() {
		return nil, false
	}
	mb := r.cache
	r.cache = nil
	return mb, true
}

// UnderlyingReader returns the wrapped reader.
func (r *cachedReader) UnderlyingReader() buf.TimeoutReader {
	return r.reader
}
