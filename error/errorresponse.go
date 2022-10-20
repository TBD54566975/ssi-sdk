package error

import (
	"fmt"
	"github.com/pkg/errors"
)

type (
	ErrorType string
)

const (
	ApplicationError ErrorType = "ApplicationError"
	CriticalError    ErrorType = "CriticalError"
	UnknownError     ErrorType = "UnknownError"
)

type ErrorResponse struct {
	Valid     bool
	Err       error
	ErrorType ErrorType
}

func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("valid %v: err %v, error type: %s", r.Valid, r.Err, r.ErrorType)
}

func NewErrorResponse(errorMessage string, errorType ErrorType) *ErrorResponse {
	return &ErrorResponse{
		Valid:     isValid(errorType),
		ErrorType: errorType,
		Err:       errors.New(errorMessage),
	}
}

func NewErrorResponseWithError(err error, errorType ErrorType) *ErrorResponse {
	return &ErrorResponse{
		Valid:     isValid(errorType),
		ErrorType: errorType,
		Err:       err,
	}
}

// GetErrorResponse will get the type of err, if the type is a ErrorResponse it will return that as an ErrorResponse, otherwise it will construct a new default ErrorResponse
func GetErrorResponse(err error) ErrorResponse {
	var errRes *ErrorResponse

	if errors.As(err, &errRes) {
		return *errRes
	}

	return ErrorResponse{Valid: false, Err: err, ErrorType: UnknownError}
}

func isValid(errorType ErrorType) bool {
	if errorType == ApplicationError {
		return true
	}
	return false
}
