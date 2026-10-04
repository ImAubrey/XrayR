// Package blackhole is an outbound handler that blocks all connections.
package blackhole

import (
	"context"
	"net/http"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	"github.com/ImAubrey/acore/common/session"
	"github.com/ImAubrey/acore/transport"
	"github.com/ImAubrey/acore/transport/internet"
)

const (
	http204InitialReadTimeout = 20 * time.Millisecond
	http204KeepAliveTimeout   = 300 * time.Millisecond
)

// Handler is an outbound connection that silently swallow the entire payload.
type Handler struct {
	response ResponseConfig
}

// New creates a new blackhole handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	response, err := config.GetInternalResponse()
	if err != nil {
		return nil, err
	}
	return &Handler{
		response: response,
	}, nil
}

// Process implements OutboundHandler.Dispatch().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	ob.Name = "blackhole"

	if isHTTPNoContentResponse(h.response) {
		return h.processHTTPNoContent(link)
	}

	nBytes := h.response.WriteTo(link.Writer)
	if nBytes > 0 {
		return common.Close(link.Writer)
	}
	common.Interrupt(link.Writer)
	return nil
}

func isHTTPNoContentResponse(response ResponseConfig) bool {
	customResponse, ok := response.(*HTTPCustomResponse)
	return ok && customResponse.GetStatusCode() == http.StatusNoContent
}

func (h *Handler) processHTTPNoContent(link *transport.Link) error {
	timeoutReader, _ := link.Reader.(buf.TimeoutReader)
	if timeoutReader == nil {
		if nBytes := h.response.WriteTo(link.Writer); nBytes > 0 {
			return common.Close(link.Writer)
		}
		common.Interrupt(link.Writer)
		return nil
	}

	_, err := readAndDiscard(timeoutReader, http204InitialReadTimeout)
	if err != nil && err != buf.ErrReadTimeout {
		return common.Close(link.Writer)
	}
	if nBytes := h.response.WriteTo(link.Writer); nBytes == 0 {
		common.Interrupt(link.Writer)
		return nil
	}

	for {
		hasData, err := readAndDiscard(timeoutReader, http204KeepAliveTimeout)
		if hasData {
			if nBytes := h.response.WriteTo(link.Writer); nBytes == 0 {
				common.Interrupt(link.Writer)
				return nil
			}
		}
		if err != nil {
			return common.Close(link.Writer)
		}
	}
}

func readAndDiscard(reader buf.TimeoutReader, timeout time.Duration) (bool, error) {
	mb, err := reader.ReadMultiBufferTimeout(timeout)
	hasData := !mb.IsEmpty()
	buf.ReleaseMulti(mb)
	return hasData, err
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}
