package error

import (
	"fmt"
	"github.com/pkg/errors"
	"reflect"
	"strings"
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
	errResponseTypeString := reflect.TypeOf(ErrorResponse{}).String()
	errTypeString := reflect.TypeOf(err).String()

	// take out pointers for comparison
	errResponseTypeString = strings.Replace(errResponseTypeString, "*", "", -1)
	errTypeString = strings.Replace(errTypeString, "*", "", -1)

	// if this is an og error wrap it into an ErrorResponse
	if errResponseTypeString != errTypeString {
		return ErrorResponse{Valid: false, Err: err, ErrorType: UnknownError}
	}

	// otherwise get an error response
	errRes := err.(*ErrorResponse)
	return *errRes
}

func isValid(errorType ErrorType) bool {
	if errorType == ApplicationError {
		return true
	}
	return false
}
