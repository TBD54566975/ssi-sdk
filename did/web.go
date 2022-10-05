package did

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/util"
)

// did:web method specification https://w3c-ccg.github.io/did-method-web/
// DID Web create and resolve methods are implemented in this package but NOT the update and deactivate methods
// please refer to web_test.go for example and test cases
type (
	DIDWeb string
)

const (
	DIDWebWellKnownURLPath = ".well-known/"
	DIDWebDIDDocFilename   = "did.json"
	DIDWebPrefix           = "did:web"
)

func (d DIDWeb) IsValid() bool {
	_, err := d.Resolve()
	return err == nil
}

func (d DIDWeb) ToString() string {
	return string(d)
}

func (d DIDWeb) Suffix() (string, error) {
	split := strings.Split(d.ToString(), DIDWebPrefix+":")
	if len(split) != 2 {
		return "", errors.Wrap(util.InvalidFormatError, "did is malformed")
	}
	return split[1], nil
}

func (d DIDWeb) Method() Method {
	return WebMethod
}

// CreateDoc constructs a did:web DIDDocument from a specific key type and its corresponding public key. This method
// does not attempt to validate that the provided public key is of the specified key type. The returned DIDDocument is
// expected further turned into a JSON file named did.json and stored under the expected path of the target web domain
// specification: https://w3c-ccg.github.io/did-method-web/#create-register
func (d DIDWeb) CreateDoc(kt crypto.KeyType, publicKey []byte) (*DIDDocument, error) {
	ldKeyType, err := KeyTypeToLDKeyType(kt)
	if err != nil {
		logrus.WithError(err).Error()
		return nil, err
	}
	didWebStr := string(d)
	keyReference := didWebStr + "#owner"

	verificationMethod, err := constructVerificationMethod(didWebStr, keyReference, publicKey, ldKeyType)
	if err != nil {
		errMsg := fmt.Sprintf("could not construct verification method for DIDWeb %+v", d)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	verificationMethodSet := []VerificationMethodSet{
		[]string{keyReference},
	}

	return &DIDDocument{
		Context:            KnownDIDContext,
		ID:                 didWebStr,
		VerificationMethod: []VerificationMethod{*verificationMethod},
		Authentication:     verificationMethodSet,
		AssertionMethod:    verificationMethodSet,
	}, nil
}

// CreateDocBytes simply takes the output from CreateDoc and returns the bytes of the JSON DID document
func (d DIDWeb) CreateDocBytes(kt crypto.KeyType, publicKey []byte) ([]byte, error) {
	doc, err := d.CreateDoc(kt, publicKey)
	if err != nil {
		logrus.WithError(err).Errorf("could not create DIDDocument for DIDWeb %+v", d)
		return nil, err
	}
	return json.Marshal(doc)
}

// GetDocURL returns the expected URL of the DID Document where https:// prefix is required by the specification
// optional path supported
func (d DIDWeb) GetDocURL() (string, error) {
	// DIDWeb must be prefixed with d:web:
	if !strings.HasPrefix(string(d), DIDWebPrefix) {
		err := fmt.Errorf("did:web DID %+v is missing prefix %s", d, DIDWebPrefix)
		logrus.WithError(err).Error()
		return "", err
	}

	subStrs := strings.Split(string(d), ":")
	numSubStrs := len(subStrs)
	if numSubStrs < 3 || len(subStrs[2]) < 1 {
		err := fmt.Errorf("d:web DID %+v is missing the required domain", d)
		logrus.WithError(err).Error()
		return "", err
	}

	// Specification https://w3c-ccg.github.io/did-method-web/#read-resolve
	// 2. If the domain contains a port percent decode the colon.
	decodedDomain, err := url.QueryUnescape(subStrs[2])
	if err != nil {
		errMsg := fmt.Sprintf("url.QueryUnescape failed for subStr %s", subStrs[2])
		return "", util.LoggingErrorMsg(err, errMsg)
	}

	// 3. Generate an HTTPS URL to the expected location of the DID document by prepending https://.
	if numSubStrs == 3 {
		// 4. If no path has been specified in the URL, append /.well-known.
		// 5. Append /d.json to complete the URL.
		urlStr := "https://" + decodedDomain + "/" + DIDWebWellKnownURLPath + DIDWebDIDDocFilename
		return urlStr, nil
	}

	// https://w3c-ccg.github.io/did-method-web/#optional-path-considerations
	// Optional Path Considerations
	var sb strings.Builder
	sb.WriteString("https://" + decodedDomain + "/")
	for i := 3; i < numSubStrs; i++ {
		str, err := url.QueryUnescape(subStrs[i])
		if err != nil {
			logrus.WithError(err).Errorf("url.QueryUnescape failed for subStr %s", subStrs[i])
			return "", err
		}
		sb.WriteString(str + "/")
	}
	sb.WriteString(DIDWebDIDDocFilename)
	return sb.String(), nil
}

// ResolveDocBytes simply performs a http.Get
// on the expected URL of the DID Document from GetDocURL
// and returns the bytes of the fetched file
func (d DIDWeb) ResolveDocBytes() ([]byte, error) {
	docURL, err := d.GetDocURL()
	if err != nil {
		logrus.WithError(err).Errorf("could not resolve DIDWeb %+v", d)
		return nil, err
	}
	// Specification https://w3c-ccg.github.io/did-method-web/#read-resolve
	// 6. Perform an HTTP GET request to the URL using an agent that can successfully negotiate a secure HTTPS
	// connection, which enforces the security requirements as described in 2.5 Security and privacy considerations.
	resp, err := http.Get(docURL)
	if err != nil {
		logrus.WithError(err).Errorf("could not resolve with docURL %+v", docURL)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.WithError(err).Errorf("could not resolve with response %+v", resp)
		return nil, err
	}
	return body, nil
}

// Resolve fetches and returns the DIDDocument from the expected URL
// specification: https://w3c-ccg.github.io/did-method-web/#read-resolve
func (d DIDWeb) Resolve() (*DIDDocument, error) {
	docBytes, err := d.ResolveDocBytes()
	if err != nil {
		errMsg := fmt.Sprintf("could not resolve DIDWeb %+v", d)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	var doc DIDDocument
	if err = json.Unmarshal(docBytes, &doc); err != nil {
		errMsg := fmt.Sprintf("could not resolve with docBytes %s", docBytes)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	if doc.ID != string(d) {
		errMsg := fmt.Sprintf("doc.ID %+v does not match DIDWeb %+v", doc.ID, d)
		return nil, util.LoggingNewError(errMsg)
	}
	return &doc, nil
}
