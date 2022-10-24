package error

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestErrorResponse(t *testing.T) {
	t.Run("simple error", func(tt *testing.T) {
		err := standardErr()
		resp := GetErrorResponse(err)

		assert.Equal(tt, resp.Valid, false)
		assert.Equal(tt, resp.ErrorType, UnknownError)
		assert.Equal(tt, resp.Err, err)
	})

	t.Run("error response with string", func(tt *testing.T) {
		err := errResponse()
		resp := GetErrorResponse(err)

		assert.Equal(tt, resp.Valid, true)
		assert.Equal(tt, resp.ErrorType, ApplicationError)
		assert.Equal(tt, resp.Err, err.(*Response).Err)
	})

	t.Run("error response with string", func(tt *testing.T) {
		err := errResponseWithErr()
		resp := GetErrorResponse(err)

		assert.Equal(tt, resp.Valid, false)
		assert.Equal(tt, resp.ErrorType, CriticalError)
		assert.Equal(tt, resp.Err, err.(*Response).Err)
	})

	t.Run("error response with formatted string", func(tt *testing.T) {
		err := errResponseWithFormattedMsg()
		resp := GetErrorResponse(err)

		assert.Equal(tt, resp.Valid, false)
		assert.Equal(tt, resp.ErrorType, ApplicationError)
		assert.Equal(tt, resp.Err, err.(*Response).Err)
		assert.Contains(tt, resp.Error(), "the best number: 5")
	})
}

func standardErr() error {
	return errors.New("this is a normal error")
}

func errResponse() error {
	return NewErrorResponse(ApplicationError, "this is error response with message")
}

func errResponseWithErr() error {
	err := errors.New("this is error response with error")
	return NewErrorResponseWithError(CriticalError, err)
}

func errResponseWithFormattedMsg() error {
	return NewErrorResponsef(CriticalError, "check out this error and the best number: %d", 5)
}
