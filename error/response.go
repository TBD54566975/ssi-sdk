package error

import (
	"fmt"

	"github.com/pkg/errors"
)

type (
	Type string
)

const (
	ApplicationError Type = "ApplicationError"
	CriticalError    Type = "CriticalError"
	UnknownError     Type = "UnknownError"
)

type Response struct {
	Valid     bool
	Err       error
	ErrorType Type
}

func (r *Response) Error() string {
	return fmt.Sprintf("valid %v: err %v, error type: %s", r.Valid, r.Err, r.ErrorType)
}

func NewErrorResponse(errorType Type, errorMessage string) *Response {
	return &Response{
		Valid:     isValid(errorType),
		ErrorType: errorType,
		Err:       errors.New(errorMessage),
	}
}

func NewErrorResponsef(errorType Type, format string, a ...interface{}) *Response {
	return &Response{
		Valid:     false,
		ErrorType: ApplicationError,
		Err:       errors.Errorf(format, a...),
	}
}

func NewErrorResponseWithError(errorType Type, err error) *Response {
	return &Response{
		Valid:     isValid(errorType),
		ErrorType: errorType,
		Err:       err,
	}
}

// GetErrorResponse will get the type of err, if the type is a ErrorResponse it will return that as an ErrorResponse, otherwise it will construct a new default ErrorResponse
func GetErrorResponse(err error) Response {
	var errRes *Response

	if errors.As(err, &errRes) {
		return *errRes
	}

	return Response{Valid: false, Err: err, ErrorType: UnknownError}
}

func isValid(errorType Type) bool {
	if errorType == ApplicationError {
		return true
	}
	return false
}
