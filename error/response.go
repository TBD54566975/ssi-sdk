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

func (r *Response) IsUnknownError() bool {
	return r == nil || r.ErrorType == UnknownError
}

func NewErrorResponse(errorType Type, errorMessage string) *Response {
	return &Response{
		Valid:     isApplicationErr(errorType),
		ErrorType: errorType,
		Err:       errors.New(errorMessage),
	}
}

func NewErrorResponsef(errorType Type, msg string, a ...any) *Response {
	return &Response{
		Valid:     isApplicationErr(errorType),
		ErrorType: errorType,
		Err:       errors.Errorf(msg, a...),
	}
}

func NewErrorResponseWithError(errorType Type, err error) *Response {
	return &Response{
		Valid:     isApplicationErr(errorType),
		ErrorType: errorType,
		Err:       err,
	}
}

func NewErrorResponseWithErrorAndMsg(errorType Type, err error, msg string) *Response {
	return &Response{
		Valid:     isApplicationErr(errorType),
		ErrorType: errorType,
		Err:       errors.Wrap(err, msg),
	}
}

func NewErrorResponseWithErrorAndMsgf(errorType Type, err error, msg string, a ...any) *Response {
	return &Response{
		Valid:     isApplicationErr(errorType),
		ErrorType: errorType,
		Err:       errors.Wrapf(err, msg, a...),
	}
}

// GetErrorResponse will get the type of err, if the type is a ErrorResponse it will return that as an ErrorResponse,
// otherwise it will construct a new default ErrorResponse
func GetErrorResponse(err error) Response {
	var errRes *Response

	if errors.As(err, &errRes) {
		return *errRes
	}

	return Response{Valid: false, Err: err, ErrorType: UnknownError}
}

// isApplicationError will return true if the error is a application error
// this is used to determine whether a response is valid or a 'real' error
func isApplicationErr(errorType Type) bool {
	return errorType == ApplicationError
}
