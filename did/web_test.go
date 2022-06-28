package did

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
)

const (
	didKey01 DIDWeb = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
	didWebBasic DIDWeb = "did:web:example.com"
	didWebWithPort DIDWeb = "did:web:localhost%3A8443"
	didWebOptionalPath DIDWeb = "did:web:example.com:user:alice"
	didWebToBeResolved DIDWeb = "did:web:demo.spruceid.com" //TODO: replace this with a demo domain from ssi-sdk
	didWebCannotBeResolved DIDWeb = "did:web:doesnotexist.com"
)

func TestDIDWebGetURL(t *testing.T) {
	_, err := didKey01.GetDocURL()
	assert.NotNil(t, err)
	docUrl, err := didWebBasic.GetDocURL()
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/.well-known/did.json", docUrl)
	docUrl, err = didWebWithPort.GetDocURL()
	assert.NoError(t, err)
	assert.Equal(t, "https://localhost:8443/.well-known/did.json", docUrl)
	docUrl, err = didWebOptionalPath.GetDocURL()
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/user/alice/did.json", docUrl)
}

func TestDIDWebResolveDocBytes(t *testing.T) {
	_, err := didWebToBeResolved.ResolveDocBytes()
	assert.NoError(t, err)
}

func TestDIDWebResolve(t *testing.T) {
	doc, err := didWebToBeResolved.Resolve()
	assert.NoError(t, err)
	assert.Equal(t, string(didWebToBeResolved), doc.ID)
	_, err = didWebCannotBeResolved.Resolve()
	assert.NotNil(t, err)
}

func TestDIDWebCreateDoc(t *testing.T) {
	pk, _, err := crypto.GenerateEd25519Key()
	assert.NoError(t, err)
	doc, err := didWebBasic.CreateDoc(crypto.Ed25519, pk)
	assert.NoError(t, err)
	assert.Equal(t, string(didWebBasic), doc.ID)
}

func TestDIDWebCreateDocFileBytes(t *testing.T) {
	pk, _, err := crypto.GenerateEd25519Key()
	assert.NoError(t, err)
	docBytes, err := didWebBasic.CreateDocBytes(crypto.Ed25519, pk)
	assert.NoError(t, err)
	assert.NotNil(t, docBytes)
}