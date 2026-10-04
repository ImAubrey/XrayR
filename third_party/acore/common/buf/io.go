package buf

import (
	"context"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/features/stats"
	"github.com/ImAubrey/acore/transport/internet/stat"
)

// Reader extends io.Reader with MultiBuffer.
type Reader interface {
	// ReadMultiBuffer reads content from underlying reader, and put it into a MultiBuffer.
	ReadMultiBuffer() (MultiBuffer, error)
}

// ErrReadTimeout is an error that happens with IO timeout.
var ErrReadTimeout = errors.New("IO timeout")

// TimeoutReader is a reader that returns error if Read() operation takes longer than the given timeout.
type TimeoutReader interface {
	Reader
	ReadMultiBufferTimeout(time.Duration) (MultiBuffer, error)
}

type TimeoutWrapperReader struct {
	Reader
	stats.Counter
	mb   MultiBuffer
	err  error
	done chan struct{}
}

func (r *TimeoutWrapperReader) ReadMultiBuffer() (MultiBuffer, error) {
	if r.done != nil {
		<-r.done
		r.done = nil
		if r.Counter != nil {
			r.Counter.Add(int64(r.mb.Len()))
		}
		return r.mb, r.err
	}
	r.mb, r.err = r.Reader.ReadMultiBuffer()
	if r.Counter != nil {
		r.Counter.Add(int64(r.mb.Len()))
	}
	return r.mb, r.err
}

func (r *TimeoutWrapperReader) ReadMultiBufferTimeout(duration time.Duration) (MultiBuffer, error) {
	if r.done == nil {
		r.done = make(chan struct{})
		go func() {
			r.mb, r.err = r.Reader.ReadMultiBuffer()
			close(r.done)
		}()
	}
	timeout := make(chan struct{})
	go func() {
		time.Sleep(duration)
		close(timeout)
	}()
	select {
	case <-r.done:
		r.done = nil
		if r.Counter != nil {
			r.Counter.Add(int64(r.mb.Len()))
		}
		return r.mb, r.err
	case <-timeout:
		return nil, nil
	}
}

// Writer extends io.Writer with MultiBuffer.
type Writer interface {
	// WriteMultiBuffer writes a MultiBuffer into underlying writer.
	WriteMultiBuffer(MultiBuffer) error
}

type counterWriter struct {
	Writer
	Counter stats.Counter
}

func (w *counterWriter) WriteMultiBuffer(mb MultiBuffer) error {
	size := mb.Len()
	err := w.Writer.WriteMultiBuffer(mb)
	if err == nil && w.Counter != nil {
		w.Counter.Add(int64(size))
	}
	return err
}

// WriteAllBytes ensures all bytes are written into the given writer.
func WriteAllBytes(writer io.Writer, payload []byte, c stats.Counter) error {
	wc := 0
	defer func() {
		if c != nil {
			c.Add(int64(wc))
		}
	}()

	for len(payload) > 0 {
		n, err := writer.Write(payload)
		wc += n
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func isPacketReader(reader io.Reader) bool {
	_, ok := reader.(net.PacketConn)
	return ok
}

// NewReader creates a new Reader.
// The Reader instance doesn't take the ownership of reader.
func NewReader(reader io.Reader) Reader {
	if mr, ok := reader.(Reader); ok {
		return mr
	}

	if isPacketReader(reader) {
		return &PacketReader{
			Reader: reader,
		}
	}

	_, isFile := reader.(*os.File)
	if !isFile && useReadv {
		if sc, ok := reader.(syscall.Conn); ok {
			rawConn, err := sc.SyscallConn()
			if err != nil {
				errors.LogInfoInner(context.Background(), err, "failed to get sysconn")
			} else {
				var counter stats.Counter

				if statConn, ok := reader.(*stat.CounterConnection); ok {
					reader = statConn.Connection
					counter = statConn.ReadCounter
				}
				return NewReadVReader(reader, rawConn, counter)
			}
		}
	}

	return &SingleReader{
		Reader: reader,
	}
}

// NewPacketReader creates a new PacketReader based on the given reader.
func NewPacketReader(reader io.Reader) Reader {
	if mr, ok := reader.(Reader); ok {
		return mr
	}

	return &PacketReader{
		Reader: reader,
	}
}

func isPacketWriter(writer io.Writer) bool {
	if _, ok := writer.(net.PacketConn); ok {
		return true
	}

	// If the writer doesn't implement syscall.Conn, it is probably not a TCP connection.
	if _, ok := writer.(syscall.Conn); !ok {
		return true
	}
	return false
}

// NewWriter creates a new Writer.
func NewWriter(writer io.Writer) Writer {
	if mw, ok := writer.(Writer); ok {
		return mw
	}

	iConn := writer
	var counter stats.Counter
	if statConn, ok := writer.(*stat.CounterConnection); ok {
		iConn = statConn.Connection
		counter = statConn.WriteCounter
	}

	// Some transports (e.g. AXPath) can't implement syscall.Conn, so the generic
	// packet-vs-stream heuristic below would incorrectly treat them as packet
	// writers and lose the MultiBuffer fast path. If the underlying connection
	// already supports MultiBuffer writes, use it directly (while preserving
	// optional traffic counters).
	if w, ok := iConn.(Writer); ok {
		if counter != nil {
			return &counterWriter{Writer: w, Counter: counter}
		}
		return w
	}

	if isPacketWriter(iConn) {
		return &SequentialWriter{
			Writer: writer,
		}
	}
	return &BufferToBytesWriter{
		Writer:  iConn,
		counter: counter,
	}
}
