package did

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/util"
)

// did:web method specification
// https://w3c-ccg.github.io/did-method-web/
// DID Web create and resolve methods are implemented in this package
// but NOT the update and deactivate methods
// please refer to web_test.go for example and test cases
type (
	DIDWeb string
)

const (
	DIDWebWellKnownURLPath = ".well-known/"
	DIDWebDIDDocFilename   = "did.json"
	DIDWebPrefix           = "did:web:"
)

// CreateDoc constructs a did:web DIDDocument from a specific key type and its corresponding public key
// This method does not attempt to validate that the provided public key is of the specified key type
// The returned DIDDocument is expected further turned into a JSON file named did.json
// and stored under the expected path of the target web domain
// specification: https://w3c-ccg.github.io/did-method-web/#create-register
func (did DIDWeb) CreateDoc(kt crypto.KeyType, publicKey []byte) (*DIDDocument, error) {
	ldKeyType, err := KeyTypeToLDKeyType(kt)
	if err != nil {
		logrus.WithError(err).Error()
		return nil, err
	}
	didWebStr := string(did)
	keyReference := didWebStr + "#owner"

	verificationMethod, err := constructVerificationMethod(didWebStr, keyReference, publicKey, ldKeyType)
	if err != nil {
		errMsg := fmt.Sprintf("could not construct verification method for DIDWeb %+v", did)
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
func (did DIDWeb) CreateDocBytes(kt crypto.KeyType, publicKey []byte) ([]byte, error) {
	doc, err := did.CreateDoc(kt, publicKey)
	if err != nil {
		logrus.WithError(err).Errorf("could not create DIDDocument for DIDWeb %+v", did)
		return nil, err
	}
	return json.Marshal(doc)
}

// GetDocURL returns the expected URL of the DID Document
// where https:// prefix is required by the specification
// optional path supported
func (did DIDWeb) GetDocURL() (string, error) {
	// DIDWeb must be prefixed with did:web:
	if !strings.HasPrefix(string(did), DIDWebPrefix) {
		err := fmt.Errorf("DIDWeb %+v is missing prefix %s", did, DIDWebPrefix)
		logrus.WithError(err).Error()
		return "", err
	}

	subStrs := strings.Split(string(did), ":")
	numSubStrs := len(subStrs)
	if numSubStrs < 3 {
		err := fmt.Errorf("did:web %+v is missing the required domain", did)
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
		// 5. Append /did.json to complete the URL.
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
func (did DIDWeb) ResolveDocBytes() ([]byte, error) {
	docURL, err := did.GetDocURL()
	if err != nil {
		logrus.WithError(err).Errorf("could not resolve DIDWeb %+v", did)
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
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.WithError(err).Errorf("could not resolve with response %+v", resp)
		return nil, err
	}
	return body, nil
}

// Resolve fetches and returns the DIDDocument from the expected URL
// specification: https://w3c-ccg.github.io/did-method-web/#read-resolve
func (did DIDWeb) Resolve() (*DIDDocument, error) {
	docBytes, err := did.ResolveDocBytes()
	if err != nil {
		errMsg := fmt.Sprintf("could not resolve DIDWeb %+v", did)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	var doc DIDDocument
	if err = json.Unmarshal(docBytes, &doc); err != nil {
		errMsg := fmt.Sprintf("could not resolve with docBytes %s", docBytes)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	if doc.ID != string(did) {
		errMsg := fmt.Sprintf("doc.ID %+v does not match DIDWeb %+v", doc.ID, did)
		return nil, util.LoggingNewError(errMsg)
	}
	return &doc, nil
}
