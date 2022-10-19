package error

import (
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestErrorResponse(t *testing.T) {
	t.Run("simple error", func(tt *testing.T) {
		err := doStuff()
		errResponse := GetErrorResponse(err)

		assert.Equal(tt, errResponse.Valid, false)
		assert.Equal(tt, errResponse.ErrorType, UnknownError)
		assert.Equal(tt, errResponse.Err, err)
	})

	t.Run("error response with string", func(tt *testing.T) {
		err := doOtherStuff()
		errResponse := GetErrorResponse(err)

		assert.Equal(tt, errResponse.Valid, true)
		assert.Equal(tt, errResponse.ErrorType, ApplicationError)
		assert.Equal(tt, errResponse.Err, err.(*ErrorResponse).Err)
	})

	t.Run("error response with string", func(tt *testing.T) {
		err := doOtherStuffOther()
		errResponse := GetErrorResponse(err)

		assert.Equal(tt, errResponse.Valid, false)
		assert.Equal(tt, errResponse.ErrorType, CriticalError)
		assert.Equal(tt, errResponse.Err, err.(*ErrorResponse).Err)
	})
}

func doStuff() error {
	return errors.New("this is a normal error")
}

func doOtherStuff() error {
	return NewErrorResponse("this is error response with message", ApplicationError)
}

func doOtherStuffOther() error {
	return NewErrorResponseWithError(errors.New("this is error response with error"), CriticalError)
}
