package util

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/go-playground/validator/v10"
)

const (
	ISO8601Template string = "2006-01-02T15:04:05-0700"
)

var (
	v *validator.Validate

	proc    *ld.JsonLdProcessor
	options *ld.JsonLdOptions
)

func init() {
	// golang validator
	v = validator.New()

	// JSON LD processing
	proc = ld.NewJsonLdProcessor()
	options = ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.Algorithm = "URDNA2015"
	options.ProcessingMode = ld.JsonLd_1_1
	options.ProduceGeneralizedRdf = true
}

func GetValidator() *validator.Validate {
	return v
}

func GetLDProcessor() *ld.JsonLdProcessor {
	return proc
}

func LDNormalize(document interface{}) (interface{}, error) {
	return GetLDProcessor().Normalize(document, options)
}

func GetISO8601Timestamp() string {
	return time.Now().UTC().Format(ISO8601Template)
}

func AsISO8601Timestamp(t time.Time) string {
	return t.UTC().Format(ISO8601Template)
}

func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// Copy makes a 1:1 copy of src into dst.
func Copy(src interface{}, dst interface{}) error {
	if err := validateCopy(src, dst); err != nil {
		return err
	}
	bytes, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, dst)
}

func ToJSON(i interface{}) (string, error) {
	b, err := json.Marshal(i)
	return string(b), err
}

func validateCopy(src interface{}, dst interface{}) error {
	if src == nil {
		return errors.New("src is nil")
	}
	if dst == nil {
		return errors.New("dst is nil")
	}

	// Type check
	srcType := reflect.TypeOf(src)
	dstType := reflect.TypeOf(dst)
	if srcType != dstType {
		return errors.New("type of src and dst must match")
	}

	// Kind checks
	srcKind := srcType.Kind()
	if !(srcKind == reflect.Ptr || srcKind == reflect.Slice) {
		return errors.New("src is not of kind ptr or slice")
	}
	dstKind := dstType.Kind()
	if !(dstKind == reflect.Ptr || dstKind == reflect.Slice) {
		return errors.New("dst is not of kind ptr or slice")
	}
	return nil
}

func StringPtr(s string) *string {
	return &s
}
