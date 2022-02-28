package util

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/go-playground/validator/v10"
)

const (
	ISO8601Template string = "2006-01-02T15:04:05-0700"
)

type LDProcessor struct {
	*ld.JsonLdProcessor
	*ld.JsonLdOptions
}

func NewValidator() *validator.Validate {
	return validator.New()
}

func NewLDProcessor() LDProcessor {
	// JSON LD processing
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.Algorithm = "URDNA2015"
	options.ProcessingMode = ld.JsonLd_1_1
	options.ProduceGeneralizedRdf = true
	return LDProcessor{
		JsonLdProcessor: proc,
		JsonLdOptions:   options,
	}
}

func (l LDProcessor) GetOptions() *ld.JsonLdOptions {
	return l.JsonLdOptions
}

func LDNormalize(document interface{}) (interface{}, error) {
	processor := NewLDProcessor()
	return processor.Normalize(document, processor.GetOptions())
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

type AppendError []string

func NewAppendError() *AppendError {
	return new(AppendError)
}

func NewAppendErrorFromError(err error) *AppendError {
	ae := new(AppendError)
	ae.Append(err)
	return ae
}
func (a *AppendError) Append(err error) {
	*a = append(*a, err.Error())
}

func (a *AppendError) AppendString(err string) {
	*a = append(*a, err)
}

func (a *AppendError) Error() error {
	if a == nil || len(*a) == 0 {
		return nil
	}
	return fmt.Errorf(strings.Join(*a, "\n"))
}

func Contains(needle string, haystack []string) bool {
	for _, maybe := range haystack {
		if maybe == needle {
			return true
		}
	}
	return false
}

func ArrayInterfaceToStr(have []interface{}) ([]string, error) {
	var want []string
	for _, item := range have {
		strItem, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("found non-string item in array: %v", item)
		}
		want = append(want, strItem)
	}
	return want, nil
}

// InterfaceToStrings assumes we are given an interface of either `string`, `[]string` or `[]interface{}` types
// and attempts to flatten into an array of strings
func InterfaceToStrings(have interface{}) ([]string, error) {
	// case 1: it's a string
	strVal, ok := have.(string)
	if ok {
		return []string{strVal}, nil
	}

	// case 2: it's an array of string types
	strVals, ok := have.([]string)
	if ok {
		var want []string
		for _, s := range strVals {
			want = append(want, s)
		}
		return want, nil
	}

	// case 3: it's an array of interface types
	interVals, ok := have.([]interface{})
	if ok {
		return ArrayInterfaceToStr(interVals)
	}

	return nil, errors.New("could not turn interface into strings")
}
