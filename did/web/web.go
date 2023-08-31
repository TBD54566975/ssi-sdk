package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/util"
)

// did:web method specification https://w3c-ccg.github.io/did-method-web/
// DID Web create and resolve methods are implemented in this package but NOT the update and deactivate methods
// please refer to web_test.go for example and test cases
type (
	DIDWeb string
)

const (
	WellKnownURLPath = ".well-known/"
	DIDDocFilename   = "did.json"
	Prefix           = "did:web"
)

// Validate return nil if DID is valid, otherwise the validation error.
func (d DIDWeb) Validate(ctx context.Context) error {
	docBytes, header, err := d.resolveDocBytes(ctx)
	if err != nil {
		return errors.Wrap(err, "resolving doc bytes")
	}
	contentType := header.Get("Content-Type")
	if contentType != util.JSONContentType {
		return errors.Errorf("header Content-Type received was `%s` but expected `%s`", contentType, "application/json")
	}
	var doc did.Document
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return errors.Wrap(err, "unmarshalling received bytes")
	}
	return doc.IsValid()
}

func (d DIDWeb) String() string {
	return string(d)
}

func (d DIDWeb) Suffix() (string, error) {
	split := strings.Split(d.String(), Prefix+":")
	if len(split) != 2 {
		return "", errors.Wrap(util.InvalidFormatError, "did is malformed")
	}
	return split[1], nil
}

func (DIDWeb) Method() did.Method {
	return did.WebMethod
}

// CreateDoc constructs a did:web Document from a specific key type and its corresponding public key. This method
// does not attempt to validate that the provided public key is of the specified key type. The returned Document is
// expected further turned into a JSON file named did.json and stored under the expected path of the target web domain
// specification: https://w3c-ccg.github.io/did-method-web/#create-register
func (d DIDWeb) CreateDoc(kt crypto.KeyType, publicKey []byte) (*did.Document, error) {
	didWebStr := string(d)
	keyReference := didWebStr + "#owner"

	verificationMethod, err := did.ConstructJWKVerificationMethod(keyReference, didWebStr, publicKey, kt)
	if err != nil {
		return nil, fmt.Errorf("could not construct verification method for DIDWeb %+v", d)
	}

	verificationMethodSet := []did.VerificationMethodSet{
		[]string{keyReference},
	}

	return &did.Document{
		Context:            did.KnownDIDContext,
		ID:                 didWebStr,
		VerificationMethod: []did.VerificationMethod{*verificationMethod},
		Authentication:     verificationMethodSet,
		AssertionMethod:    verificationMethodSet,
	}, nil
}

// CreateDocBytes simply takes the output from CreateDoc and returns the bytes of the JSON DID document
func (d DIDWeb) CreateDocBytes(kt crypto.KeyType, publicKey []byte) ([]byte, error) {
	doc, err := d.CreateDoc(kt, publicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create DID Document for did:web DID %+v", d)
	}
	return json.Marshal(doc)
}

// GetDocURL returns the expected URL of the DID Document where https:// prefix is required by the specification
// optional path supported
func (d DIDWeb) GetDocURL() (string, error) {
	// DIDWeb must be prefixed with d:web:
	if !strings.HasPrefix(string(d), Prefix) {
		return "", fmt.Errorf("did:web DID %+v is missing prefix %s", d, Prefix)
	}

	subStrs := strings.Split(string(d), ":")
	numSubStrs := len(subStrs)
	if numSubStrs < 3 || len(subStrs[2]) < 1 {
		return "", fmt.Errorf("did:web DID %+v is missing the required domain", d)
	}

	// Specification https://w3c-ccg.github.io/did-method-web/#read-resolve
	// 2. If the domain contains a port percent decode the colon.
	decodedDomain, err := url.QueryUnescape(subStrs[2])
	if err != nil {
		return "", errors.Wrapf(err, "url.QueryUnescape failed for subStr %s", subStrs[2])
	}

	// 3. Generate an HTTPS URL to the expected location of the DID document by prepending https://.
	if numSubStrs == 3 {
		// 4. If no path has been specified in the URL, append /.well-known.
		// 5. Append /d.json to complete the URL.
		urlStr := "https://" + decodedDomain + "/" + WellKnownURLPath + DIDDocFilename
		return urlStr, nil
	}

	// https://w3c-ccg.github.io/did-method-web/#optional-path-considerations
	// Optional Path Considerations
	var sb strings.Builder
	if _, err = sb.WriteString("https://" + decodedDomain + "/"); err != nil {
		return "", err
	}
	for i := 3; i < numSubStrs; i++ {
		str, err := url.QueryUnescape(subStrs[i])
		if err != nil {
			return "", errors.Wrapf(err, "url.QueryUnescape failed for subStr %s", subStrs[i])
		}
		if _, err = sb.WriteString(str + "/"); err != nil {
			return "", err
		}
	}
	if _, err := sb.WriteString(DIDDocFilename); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func (d DIDWeb) Resolve(ctx context.Context) (*did.Document, error) {
	docBytes, _, err := d.resolveDocBytes(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving did:web DID<%s>", d)
	}
	resolutionResult, err := resolution.ParseDIDResolution(docBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving did:web DID<%s>", d)
	}
	if resolutionResult.ID != d.String() {
		return nil, fmt.Errorf("doc.id<%s> does not match did:web value<%s>", resolutionResult.ID, d)
	}
	return &resolutionResult.Document, nil
}

// resolveDocBytes simply performs a http.Get on the expected URL of the DID Document from GetDocURL
// and returns the bytes of the fetched file
func (d DIDWeb) resolveDocBytes(ctx context.Context) ([]byte, http.Header, error) {
	docURL, err := d.GetDocURL()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "getting doc url %+v", d)
	}
	// Specification https://w3c-ccg.github.io/did-method-web/#read-resolve
	// 6. Perform an HTTP GET request to the URL using an agent that can successfully negotiate a secure HTTPS
	// connection, which enforces the security requirements as described in 2.5 Security and privacy considerations.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "constructing doc request %+v", docURL)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "getting doc %+v", docURL)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "reading response %+v", resp)
	}
	return body, resp.Header, nil
}
