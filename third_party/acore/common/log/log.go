package log // import "github.com/ImAubrey/acore/common/log"

import (
	"sync"

	"github.com/ImAubrey/acore/common/serial"
)

// Message is the interface for all log messages.
type Message interface {
	String() string
}

// Handler is the interface for log handler.
type Handler interface {
	Handle(msg Message)
}

// GeneralMessageFilter is an optional interface for log handlers that can
// cheaply decide whether a general message would be handled (e.g. based on
// severity thresholds), allowing callers to skip work on disabled severities.
type GeneralMessageFilter interface {
	EnabledGeneral(sev Severity) bool
}

// GeneralMessage is a general log message that can contain all kind of content.
type GeneralMessage struct {
	Severity Severity
	Content  interface{}
}

// String implements Message.
func (m *GeneralMessage) String() string {
	return serial.Concat("[", m.Severity, "] ", m.Content)
}

// Record writes a message into log stream.
func Record(msg Message) {
	logHandler.Handle(msg)
}

// IsGeneralMessageEnabled returns whether a GeneralMessage with the given
// severity would be handled by the currently registered handler.
//
// If no handler is registered, it returns false.
// If the handler does not implement GeneralMessageFilter, it conservatively
// returns true.
func IsGeneralMessageEnabled(sev Severity) bool {
	logHandler.RLock()
	handler := logHandler.Handler
	logHandler.RUnlock()

	if handler == nil {
		return false
	}
	if f, ok := handler.(GeneralMessageFilter); ok {
		return f.EnabledGeneral(sev)
	}
	return true
}

var logHandler syncHandler

// RegisterHandler registers a new handler as current log handler. Previous registered handler will be discarded.
func RegisterHandler(handler Handler) {
	if handler == nil {
		panic("Log handler is nil")
	}
	logHandler.Set(handler)
}

type syncHandler struct {
	sync.RWMutex
	Handler
}

func (h *syncHandler) Handle(msg Message) {
	h.RLock()
	defer h.RUnlock()

	if h.Handler != nil {
		h.Handler.Handle(msg)
	}
}

func (h *syncHandler) Set(handler Handler) {
	h.Lock()
	defer h.Unlock()

	h.Handler = handler
}
