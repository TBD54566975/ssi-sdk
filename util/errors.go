package util

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Error messages
var (
	UnsupportedError    = errors.New("not supported")
	NotImplementedError = errors.New("not implemented")
	InvalidFormatError  = errors.New("invalid format")
	UndefinedError      = errors.New("undefined")
	CastingError        = errors.New("failed to convert")
)

// LoggingError is a utility to combine logging an error, and returning and error
func LoggingError(err error) error {
	logrus.WithError(err).Error()
	return err
}

// LoggingNewError is a utility to create an error from a message, log it, and return it as an error
func LoggingNewError(msg string) error {
	err := errors.New(msg)
	logrus.WithError(err).Error()
	return err
}

// LoggingNewErrorf is a utility to create an error from a formatted message, log it, and return it as an error
func LoggingNewErrorf(msg string, args ...any) error {
	return LoggingNewError(fmt.Sprintf(msg, args...))
}

// LoggingErrorMsg is a utility to combine logging an error, and returning and error with a message
func LoggingErrorMsg(err error, msg string) error {
	logrus.WithError(err).Error(SanitizeLog(msg))
	if err == nil {
		return errors.New(msg)
	}
	return errors.Wrap(err, msg)
}

// LoggingErrorMsgf is a utility to combine logging an error, and returning and error with a formatted message
func LoggingErrorMsgf(err error, msg string, args ...any) error {
	return LoggingErrorMsg(err, fmt.Sprintf(msg, args...))
}

// SanitizeLog prevents certain classes of injection attacks before logging
// https://codeql.github.com/codeql-query-help/go/go-log-injection/
func SanitizeLog(log string) string {
	escapedLog := strings.ReplaceAll(log, "\n", "")
	return strings.ReplaceAll(escapedLog, "\r", "")
}
