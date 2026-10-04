package protocol // import "github.com/ImAubrey/acore/common/protocol"

import (
	"errors"
	"fmt"
)

var ErrProtoNeedMoreData = errors.New("protocol matches, but need more data to complete sniffing")

// NeedMoreDataError carries the minimum bytes required to continue parsing.
// It unwraps to ErrProtoNeedMoreData so existing errors.Is checks remain valid.
type NeedMoreDataError struct {
	need int
}

func (e *NeedMoreDataError) Error() string {
	if e == nil || e.need <= 0 {
		return ErrProtoNeedMoreData.Error()
	}
	return fmt.Sprintf("%s (need at least %d bytes)", ErrProtoNeedMoreData.Error(), e.need)
}

func (e *NeedMoreDataError) Unwrap() error {
	return ErrProtoNeedMoreData
}

// NewNeedMoreDataError returns an error that indicates protocol matched but
// parsing requires at least need bytes from current stream payload.
func NewNeedMoreDataError(need int) error {
	if need <= 0 {
		return ErrProtoNeedMoreData
	}
	return &NeedMoreDataError{need: need}
}

// NeedMoreDataLen extracts the minimum needed bytes from err.
func NeedMoreDataLen(err error) (int, bool) {
	var e *NeedMoreDataError
	if !errors.As(err, &e) || e == nil || e.need <= 0 {
		return 0, false
	}
	return e.need, true
}
