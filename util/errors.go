package util

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

// LoggingErrorMsg is a utility to combine logging an error, and returning and error with a message
func LoggingErrorMsg(err error, msg string) error {
	logrus.WithError(err).Error(msg)
	return errors.Wrap(err, msg)
}

// Error messages
var (
	UnsupportedError    = errors.New("not supported")
	NotImplementedError = errors.New("not implemented")
	InvalidFormatError  = errors.New("invalid format")
	UndefinedError      = errors.New("undefined")
	CastingError        = errors.New("failed to convert")
)
