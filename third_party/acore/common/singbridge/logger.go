package singbridge

import (
	"context"

	"github.com/ImAubrey/acore/common/errors"
	"github.com/sagernet/sing/common/logger"
)

var _ logger.ContextLogger = (*AcoreLogger)(nil)

type AcoreLogger struct {
	newError func(values ...any) *errors.Error
}

func NewLogger(newErrorFunc func(values ...any) *errors.Error) *AcoreLogger {
	return &AcoreLogger{
		newErrorFunc,
	}
}

func (l *AcoreLogger) Trace(args ...any) {
}

func (l *AcoreLogger) Debug(args ...any) {
	errors.LogDebug(context.Background(), args...)
}

func (l *AcoreLogger) Info(args ...any) {
	errors.LogInfo(context.Background(), args...)
}

func (l *AcoreLogger) Warn(args ...any) {
	errors.LogWarning(context.Background(), args...)
}

func (l *AcoreLogger) Error(args ...any) {
	errors.LogError(context.Background(), args...)
}

func (l *AcoreLogger) Fatal(args ...any) {
}

func (l *AcoreLogger) Panic(args ...any) {
}

func (l *AcoreLogger) TraceContext(ctx context.Context, args ...any) {
}

func (l *AcoreLogger) DebugContext(ctx context.Context, args ...any) {
	errors.LogDebug(ctx, args...)
}

func (l *AcoreLogger) InfoContext(ctx context.Context, args ...any) {
	errors.LogInfo(ctx, args...)
}

func (l *AcoreLogger) WarnContext(ctx context.Context, args ...any) {
	errors.LogWarning(ctx, args...)
}

func (l *AcoreLogger) ErrorContext(ctx context.Context, args ...any) {
	errors.LogError(ctx, args...)
}

func (l *AcoreLogger) FatalContext(ctx context.Context, args ...any) {
}

func (l *AcoreLogger) PanicContext(ctx context.Context, args ...any) {
}
