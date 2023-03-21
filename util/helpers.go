package util

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/piprate/json-gold/ld"

	"github.com/go-playground/validator/v10"
)

type LDProcessor struct {
	*ld.JsonLdProcessor
	*ld.JsonLdOptions
}

func NewValidator() *validator.Validate {
	return validator.New()
}

func IsValidStruct(data any) error {
	if t := reflect.TypeOf(data).Kind(); t != reflect.Struct {
		return fmt.Errorf("provided data is not of Kind struct: %+v", data)
	}
	return NewValidator().Struct(data)
}

func NewLDProcessor() LDProcessor {
	// JSON LD processing
	proc := ld.NewJsonLdProcessor()
	// Initialize a new doc loader with caching capability
	// LDProcessor is expected to be re-used for multiple json-ld operations
	docLoader := ld.NewRFC7324CachingDocumentLoader(nil)
	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.Algorithm = "URDNA2015"
	options.ProcessingMode = ld.JsonLd_1_1
	options.ProduceGeneralizedRdf = true
	options.DocumentLoader = docLoader
	return LDProcessor{
		JsonLdProcessor: proc,
		JsonLdOptions:   options,
	}
}

func (l LDProcessor) GetOptions() *ld.JsonLdOptions {
	return l.JsonLdOptions
}

func (l LDProcessor) GetContextFromMap(dataMap map[string]any) (*ld.Context, error) {
	var activeCtx *ld.Context
	var err error
	ldCtx := ld.NewContext(nil, l.JsonLdOptions)
	contextMap, ok := dataMap["@context"].(map[string]any)
	if !ok {
		activeCtx, err = ldCtx.Parse(dataMap)
	} else {
		activeCtx, err = ldCtx.Parse(contextMap)
	}
	if err != nil {
		return nil, err
	}
	return activeCtx, nil
}

func LDNormalize(document any) (any, error) {
	processor := NewLDProcessor()
	return processor.Normalize(document, processor.GetOptions())
}

// LDFrame runs https://www.w3.org/TR/json-ld11-framing/ to transform the data in a document according to its frame
func LDFrame(document interface{}, frame interface{}) (interface{}, error) {
	docAny := document
	var err error
	if _, ok := document.(map[string]interface{}); !ok {
		docAny, err = AnyToJSONInterface(document)
		if err != nil {
			return nil, err
		}
	}

	frameAny := frame
	if _, ok := frame.(map[string]interface{}); !ok {
		frameAny, err = AnyToJSONInterface(frame)
		if err != nil {
			return nil, err
		}
	}
	docLoader := ld.NewRFC7324CachingDocumentLoader(nil)
	// use the aries processor for special framing logic necessary for blank nodes
	return jsonld.Default().Frame(docAny.(map[string]interface{}),
		frameAny.(map[string]interface{}), jsonld.WithDocumentLoader(docLoader), jsonld.WithFrameBlankNodes())
}

// LDCompact runs https://www.w3.org/TR/json-ld-api/#compaction-algorithms which shortens IRIs in the document
func LDCompact(document interface{}, context string) (map[string]interface{}, error) {
	processor := NewLDProcessor()
	contextsMap := map[string]interface{}{
		"@context": context,
	}
	return processor.Compact(document, contextsMap, processor.GetOptions())
}

func GetRFC3339Timestamp() string {
	return AsRFC3339Timestamp(time.Now())
}

func AsRFC3339Timestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// IsRFC3339Timestamp attempts to parse a string as an RFC3339 timestamp, which is a subset of an
// ISO-8601 timestamp. Returns true if the parsing is successful, false if not.
func IsRFC3339Timestamp(t string) bool {
	_, err := time.Parse(time.RFC3339, t)
	return err == nil
}

// Copy makes a 1:1 copy of src into dst.
func Copy(src any, dst any) error {
	if err := validateCopy(src, dst); err != nil {
		return err
	}
	bytes, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, dst)
}

func ToJSON(i any) (string, error) {
	b, err := json.Marshal(i)
	return string(b), err
}

func ToJSONInterface(data string) (any, error) {
	var result any
	err := json.Unmarshal([]byte(data), &result)
	return result, err
}

func AnyToJSONInterface(data interface{}) (interface{}, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var result interface{}
	err = json.Unmarshal(dataBytes, &result)
	return result, err
}

func validateCopy(src any, dst any) error {
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

func (a *AppendError) IsEmpty() bool {
	return a == nil || len(*a) == 0
}

func (a *AppendError) NumErrors() int {
	if a == nil {
		return 0
	}
	return len(*a)
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

func ArrayInterfaceToStr(have []any) ([]string, error) {
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

func ArrayStrToInterface(have []string) []any {
	var want []any
	for _, v := range have {
		want = append(want, v)
	}
	return want
}

// InterfaceToInterfaceArray attempts to array-ify an interface type
func InterfaceToInterfaceArray(have any) ([]any, error) {
	// case 1: it's a string
	strVal, ok := have.(string)
	if ok {
		return []any{strVal}, nil
	}

	// case 2: it's an array of string types
	strVals, ok := have.([]string)
	if ok {
		var want []any
		for _, s := range strVals {
			want = append(want, s)
		}
		return want, nil
	}

	// case 3: it's an array of interface types
	interVals, ok := have.([]any)
	if ok {
		return interVals, nil
	}

	// case 4: it's another interface type
	return []any{have}, nil
}

// InterfaceToStrings assumes we are given an interface of either `string`, `[]string` or `[]any` types
// and attempts to flatten into an array of strings
func InterfaceToStrings(have any) ([]string, error) {
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
	interVals, ok := have.([]any)
	if ok {
		return ArrayInterfaceToStr(interVals)
	}

	return nil, errors.New("could not turn interface into strings")
}

func ToJSONMap(data any) (map[string]any, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var jsonMap map[string]any
	if err := json.Unmarshal(dataBytes, &jsonMap); err != nil {
		return nil, err
	}
	return jsonMap, nil
}

// MergeUniqueValues takes in two string arrays and returns the union set
// the input arrays are not modified
func MergeUniqueValues(a, b []string) []string {
	seen := make(map[string]bool)
	var res []string
	for _, v := range a {
		// this check is necessary if a contains duplicates
		if _, s := seen[v]; !s {
			res = append(res, v)
			seen[v] = true
		}
	}
	for _, v := range b {
		if _, s := seen[v]; !s {
			res = append(res, v)
		}
	}
	return res
}

// PrettyJSON JSON-ifies data in a 'pretty-print' fashion
func PrettyJSON(data any) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}
