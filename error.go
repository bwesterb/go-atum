package atum

import (
	"fmt"
)

type Error interface {
	error
	Inner() error // Returns the wrapped error, if any
}

type errorImpl struct {
	msg   string
	inner error
}

func (err *errorImpl) Inner() error { return err.inner }

func (err *errorImpl) Error() string {
	if err.inner != nil {
		return fmt.Sprintf("%s: %s", err.msg, err.inner.Error())
	}
	return err.msg
}

// Formats a new Error
func errorf(format string, a ...interface{}) *errorImpl {
	return &errorImpl{msg: fmt.Sprintf(format, a...)}
}

// Formats a new Error that wraps another
func wrapErrorf(err error, format string, a ...interface{}) *errorImpl {
	return &errorImpl{msg: fmt.Sprintf(format, a...), inner: err}
}
