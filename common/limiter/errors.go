package limiter

import "github.com/ImAubrey/acore/common/errors"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
