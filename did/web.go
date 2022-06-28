package did

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
)

// did:web method specification
// https://w3c-ccg.github.io/did-method-web/
// DID Web create and resolve mothods are implemented in this package
// but NOT the update and deactivate methods
// please refer to web_test.go for example and test cases
type DIDWeb string

const (
	DID_WEB_WELL_KNOWN_URL_PATH = ".well-known/"
	DID_WEB_DID_DOC_NAME        = "did.json"
)

// CreateDoc constructs a did:web DIDDocument from a specific key type and its corresponding public key
// This method does not attempt to validate that the provided public key is of the specified key type
// The returned DIDDoucment is expected further turned into a JSON file named did.json
// and stored under the expected path of the target web domain
// specification: https://w3c-ccg.github.io/did-method-web/#create-register
func (did DIDWeb) CreateDoc(kt crypto.KeyType, publicKey []byte) (*DIDDocument, error) {
	//create DIDKey with publicKey
	didKey, err := CreateDIDKey(kt, publicKey)
	if err != nil {
		return nil, err
	}
	//create DIDDocument
	didDoc, err := didKey.Expand()
	if err != nil {
		return nil, err
	}
	didWebStr := string(did)
	didDoc.ID = didWebStr
	verMethodID := didWebStr + "#owner"
	didDoc.VerificationMethod[0].ID = verMethodID
	didDoc.VerificationMethod[0].Controller = didWebStr
	didDoc.Authentication[0] = verMethodID
	didDoc.AssertionMethod[0] = verMethodID

	return didDoc, nil
}

// CreateDocBytes simply takes the output from CreateDoc and returns the bytes of the JSON DID document
func (did DIDWeb) CreateDocBytes(kt crypto.KeyType, publicKey []byte) ([]byte, error) {
	doc, err := did.CreateDoc(kt, publicKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

// GetDocURL returns the expected URL of the DID Document
// where https:// prefix is required by the specification
// optional path supported
func (did DIDWeb) GetDocURL() (string, error) {
	//DIDWeb must be prefixed with did:web:
	if !strings.HasPrefix(string(did), "did:web:") {
		return "", fmt.Errorf("%+v not a valid did:web", did)
	}

	subStrs := strings.Split(string(did), ":")
	numSubStrs := len(subStrs)
	if numSubStrs < 3 || subStrs[0] != "did" || subStrs[1] != "web" {
		return "", fmt.Errorf("%+v not a valid did:web", did)
	}
	decodedDomain, err := url.QueryUnescape(subStrs[2])
	if err != nil {
		return "", err
	}

	//with well-known path
	if numSubStrs == 3 {
		urlStr := "https://" + decodedDomain + "/" + DID_WEB_WELL_KNOWN_URL_PATH + DID_WEB_DID_DOC_NAME
		return urlStr, nil
	}

	//with optional path
	var sb strings.Builder
	sb.WriteString("https://" + decodedDomain + "/")
	for i := 3; i < numSubStrs; i++ {
		str, err := url.QueryUnescape(subStrs[i])
		if err != nil {
			return "", err
		}
		sb.WriteString(str + "/")
	}
	sb.WriteString(DID_WEB_DID_DOC_NAME)
	return sb.String(), nil
}

// ResolveDocBytes simply performs a http.Get
// on the expected URL of the DID Document from GetDocURL
// and returns the bytes of the fetched file
func (did DIDWeb) ResolveDocBytes() ([]byte, error) {
	docUrl, err := did.GetDocURL()
	if err != nil {
		return nil, err
	}
	resp, err := http.Get(docUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// IsValidDoc performs a minimal check on the DIDDocument
// and make sure the Document's ID is the same as the DIDWeb
func (did DIDWeb) IsValidDoc(doc DIDDocument) bool {
	if len(doc.ID) == 0 || len(doc.VerificationMethod) == 0 || len(doc.Authentication) == 0 || len(doc.AssertionMethod) == 0 {
		return false
	}
	return DIDWeb(doc.ID) == did
}

// Resolve fetchs and returns the DIDDocument from the expected URL
// specification: https://w3c-ccg.github.io/did-method-web/#read-resolve
func (did DIDWeb) Resolve() (*DIDDocument, error) {
	docBytes, err := did.ResolveDocBytes()
	if err != nil {
		return nil, err
	}
	var doc DIDDocument
	err = json.Unmarshal(docBytes, &doc)
	if err != nil {
		return nil, err
	}
	if !did.IsValidDoc(doc) {
		return nil, fmt.Errorf("Invalid doc for %+v: %+v", did, did)
	}
	return &doc, nil
}
