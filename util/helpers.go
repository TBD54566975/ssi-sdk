package util

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/goccy/go-json"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/piprate/json-gold/ld"
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

//go:embed known_contexts/w3c_2018_credentials_v1.json
var w3c2018CredentialsV1 string

//go:embed known_contexts/w3c_2018_credentials_examples_v1.json
var w3c2018CredentialsExamplesV1 string

//go:embed known_contexts/w3c_ns_did_v1.json
var w3cNamespaceDIDV1 string

//go:embed known_contexts/w3c_vc_di_bbs_contexts_v1.json
var w3cVCDIBBSV1 string

//go:embed known_contexts/w3c_jws_2020_v1.json
var w3cJWS2020V1 string

//go:embed known_contexts/w3id_security_v1.json
var w3idSecurityV1 string

//go:embed known_contexts/w3id_security_v2.json
var w3idSecurityV2 string

//go:embed known_contexts/w3id_citizenship_v1.json
var w3idCitizenshipV1 string

//go:embed known_contexts/w3_ns_odrl.json
var w3NamespaceODRL string

func NewLDProcessor() (*LDProcessor, error) {
	// JSON LD processing
	proc := ld.NewJsonLdProcessor()

	// Initialize a new doc loader with caching capability
	// LDProcessor is expected to be re-used for multiple json-ld operations
	docLoader, err := NewLDDocumentLoader()
	if err != nil {
		return nil, err
	}
	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.Algorithm = "URDNA2015"
	options.ProcessingMode = ld.JsonLd_1_1
	options.ProduceGeneralizedRdf = true
	options.DocumentLoader = docLoader
	return &LDProcessor{
		JsonLdProcessor: proc,
		JsonLdOptions:   options,
	}, nil
}

func NewLDDocumentLoader() (*ld.CachingDocumentLoader, error) {
	rfcDocLoader := ld.NewRFC7324CachingDocumentLoader(nil)
	docLoader := ld.NewCachingDocumentLoader(rfcDocLoader)

	// We cache the contexts we know we'll use over and over.
	if err := preloadContext(docLoader, w3c2018CredentialsV1, "https://www.w3.org/2018/credentials/v1"); err != nil {
		return nil, err
	}
	if err := preloadContext(docLoader, w3c2018CredentialsExamplesV1, "https://www.w3.org/2018/credentials/examples/v1"); err != nil {
		return nil, err
	}
	if err := preloadContext(docLoader, w3cNamespaceDIDV1, "https://www.w3.org/ns/did/v1"); err != nil {
		return nil, err
	}
	if err := preloadContext(docLoader, w3cVCDIBBSV1, "https://w3c.github.io/vc-di-bbs/contexts/v1"); err != nil {
		return nil, err
	}
	if err := preloadContext(docLoader, w3cJWS2020V1, "https://w3id.org/security/suites/jws-2020/v1"); err != nil {
		return nil, err
	}
	if err := preloadContext(docLoader, w3idSecurityV1, "https://w3id.org/security/v1"); err != nil {
		return nil, err
	}
	if err := preloadContext(docLoader, w3idSecurityV2, "https://w3id.org/security/v2"); err != nil {
		return nil, err
	}
	if err := preloadContext(docLoader, w3idCitizenshipV1, "https://w3id.org/citizenship/v1"); err != nil {
		return nil, err
	}
	if err := preloadContext(docLoader, w3NamespaceODRL, "https://www.w3.org/ns/odrl.jsonld"); err != nil {
		return nil, err
	}
	return docLoader, nil
}

func preloadContext(docLoader *ld.CachingDocumentLoader, contents string, url string) error {
	f, err := os.CreateTemp("", "")
	if err != nil {
		return err
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(f.Name())
	if _, err := f.Write([]byte(contents)); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return docLoader.PreloadWithMapping(map[string]string{
		url: f.Name(),
	})
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
	processor, err := NewLDProcessor()
	if err != nil {
		return nil, err
	}
	return processor.Normalize(document, processor.GetOptions())
}

// LDFrame runs https://www.w3.org/TR/json-ld11-framing/ to transform the data in a document according to its frame
func LDFrame(document any, frame any) (any, error) {
	docAny := document
	var err error
	if _, ok := document.(map[string]any); !ok {
		docAny, err = AnyToJSONInterface(document)
		if err != nil {
			return nil, err
		}
	}

	frameAny := frame
	if _, ok := frame.(map[string]any); !ok {
		frameAny, err = AnyToJSONInterface(frame)
		if err != nil {
			return nil, err
		}
	}
	docLoader, err := NewLDDocumentLoader()
	if err != nil {
		return nil, err
	}
	// use the aries processor for special framing logic necessary for blank nodes
	return jsonld.Default().Frame(docAny.(map[string]any),
		frameAny.(map[string]any), jsonld.WithDocumentLoader(docLoader), jsonld.WithFrameBlankNodes())
}

// LDCompact runs https://www.w3.org/TR/json-ld-api/#compaction-algorithms which shortens IRIs in the document
func LDCompact(document any, context string) (map[string]any, error) {
	processor, err := NewLDProcessor()
	if err != nil {
		return nil, err
	}
	contextsMap := map[string]any{
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

func ToJSONInterface(data string) (any, error) {
	var result any
	err := json.Unmarshal([]byte(data), &result)
	return result, err
}

func AnyToJSONInterface(data any) (any, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var result any
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
