package blackhole_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/serial"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/proxy/blackhole"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/pipe"
)

func TestBlackholeHTTPResponse(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: serial.ToTypedMessage(&blackhole.HTTPResponse{}),
	})
	common.Must(err)

	reader, writer := pipe.New(pipe.WithoutSizeLimit())

	type readResult struct {
		mb  buf.MultiBuffer
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		b, e := reader.ReadMultiBuffer()
		done <- readResult{mb: b, err: e}
	}()

	link := transport.Link{
		Reader: reader,
		Writer: writer,
	}
	common.Must(handler.Process(ctx, &link, nil))
	result := <-done
	common.Must(result.err)
	if result.mb.IsEmpty() {
		t.Error("expect http response, but nothing")
	}
}

func TestBlackholeCustomHTTPResponseClosesWithoutDelay(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: serial.ToTypedMessage(&blackhole.HTTPCustomResponse{
			StatusCode: 204,
		}),
	})
	common.Must(err)

	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	link := transport.Link{
		Writer: writer,
	}

	start := time.Now()
	common.Must(handler.Process(ctx, &link, nil))
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatal("expected blackhole response to close without fixed delay, took ", elapsed)
	}

	mb, err := reader.ReadMultiBuffer()
	common.Must(err)
	defer buf.ReleaseMulti(mb)
	if mb.IsEmpty() {
		t.Fatal("expect http response, but nothing")
	}

	mb, err = reader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err != io.EOF {
		t.Fatal("expected EOF after response, got ", err)
	}
}

func TestBlackholeCustomHTTP204RespondsToRepeatedRequests(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: serial.ToTypedMessage(&blackhole.HTTPCustomResponse{
			StatusCode: 204,
		}),
	})
	common.Must(err)

	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())

	writeString(t, uplinkWriter, "HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n\r\n")

	link := transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}
	done := make(chan error, 1)
	go func() {
		done <- handler.Process(ctx, &link, nil)
	}()

	readNonEmptyWithin(t, downlinkReader, 200*time.Millisecond)
	if mb, err := downlinkReader.ReadMultiBufferTimeout(50 * time.Millisecond); err != buf.ErrReadTimeout {
		buf.ReleaseMulti(mb)
		t.Fatal("unexpected extra response before the second request: ", err)
	}

	writeString(t, uplinkWriter, "HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n\r\n")
	readNonEmptyWithin(t, downlinkReader, 200*time.Millisecond)

	common.Must(common.Close(uplinkWriter))
	select {
	case err := <-done:
		common.Must(err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blackhole http-204 handler did not exit after uplink close")
	}

	mb, err := downlinkReader.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err != io.EOF {
		t.Fatal("expected EOF after handler exit, got ", err)
	}
}

func writeString(t *testing.T, writer buf.Writer, payload string) {
	t.Helper()
	b := buf.New()
	common.Must2(b.WriteString(payload))
	common.Must(writer.WriteMultiBuffer(buf.MultiBuffer{b}))
}

func readNonEmptyWithin(t *testing.T, reader *pipe.Reader, timeout time.Duration) {
	t.Helper()
	mb, err := reader.ReadMultiBufferTimeout(timeout)
	common.Must(err)
	defer buf.ReleaseMulti(mb)
	if mb.IsEmpty() {
		t.Fatal("expected non-empty response")
	}
}
