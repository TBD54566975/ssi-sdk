package web

import (
	"context"
	"testing"

	"gopkg.in/h2non/gock.v1"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/crypto"
)

const (
	didKey01               DIDWeb = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
	didWebBasic            DIDWeb = "did:web:example.com"
	didWebWithPort         DIDWeb = "did:web:localhost%3A8443"
	didWebOptionalPath     DIDWeb = "did:web:example.com:user:alice"
	didWebToBeResolved     DIDWeb = "did:web:demo.ssi-sdk.com"
	didWebCannotBeResolved DIDWeb = "did:web:doesnotexist.com"
	didWebNotADomain       DIDWeb = "did:web:"
	didWebBadQueryURL      DIDWeb = "did:web:%414802%"
)

func TestDIDWebGetURL(t *testing.T) {
	_, err := didKey01.GetDocURL()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp is missing prefix did:web")

	docURL, err := didWebBasic.GetDocURL()
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/.well-known/did.json", docURL)

	docURL, err = didWebWithPort.GetDocURL()
	assert.NoError(t, err)
	assert.Equal(t, "https://localhost:8443/.well-known/did.json", docURL)

	docURL, err = didWebOptionalPath.GetDocURL()
	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/user/alice/did.json", docURL)

	_, err = didWebNotADomain.GetDocURL()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing the required domain")

	_, err = didWebBadQueryURL.GetDocURL()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "url.QueryUnescape failed for subSt")
}

func TestDIDWebResolveDocBytes(t *testing.T) {
	t.Run("Happy Path", func(tt *testing.T) {
		gock.New("https://demo.ssi-sdk.com").
			Get("/.well-known/did.json").
			Reply(200).
			BodyString(`{"didDocument": {"id": "did:web:demo.ssi-sdk.com"}}`)
		defer gock.Off()

		docBytes, _, err := didWebToBeResolved.resolveDocBytes(context.Background())
		assert.NoError(tt, err)
		assert.Contains(tt, string(docBytes), "did:web:demo.ssi-sdk.com")
	})

	t.Run("Unresolvable Path", func(tt *testing.T) {
		_, _, err := didWebNotADomain.resolveDocBytes(context.Background())
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "did:web: is missing the required domain")
	})
}

func TestDIDWebResolve(t *testing.T) {
	t.Run("Happy Path - Known DID", func(tt *testing.T) {
		gock.New("https://demo.ssi-sdk.com").
			Get("/.well-known/did.json").
			Reply(200).
			BodyString(`{"didDocument": {"id": "did:web:demo.ssi-sdk.com"}}`)
		defer gock.Off()

		doc, err := didWebToBeResolved.Resolve(context.Background())
		assert.NoError(tt, err)
		assert.Equal(tt, string(didWebToBeResolved), doc.ID)
	})

	t.Run("Unhappy Path - Mismatched DID", func(tt *testing.T) {
		gock.New("https://doesnotexist.com").
			Get("/.well-known/did.json").
			Reply(200).
			BodyString(`{"didDocument": {"id": "did:web:demo.ssi-sdk.com"}}`)
		defer gock.Off()

		_, err := didWebCannotBeResolved.Resolve(context.Background())
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "doc.id<did:web:demo.ssi-sdk.com> does not match did:web value<did:web:doesnotexist.com>")
	})

	t.Run("Unhappy Path - Unknown DID", func(t *testing.T) {
		_, err := didWebCannotBeResolved.Resolve(context.Background())
		assert.Error(t, err)
	})
}

func TestDIDWebCreateDoc(t *testing.T) {
	t.Run("Happy Path - Create DID", func(tt *testing.T) {
		pk, _, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		doc, err := didWebBasic.CreateDoc(crypto.Ed25519, pk)
		assert.NoError(tt, err)
		assert.Equal(tt, string(didWebBasic), doc.ID)
	})

	t.Run("Unsupported Key Type", func(tt *testing.T) {
		pk, _, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		_, err = didWebBasic.CreateDoc(crypto.KeyType("bad"), pk)
		assert.Error(tt, err)
	})

	t.Run("Bad Public Key for JWK", func(tt *testing.T) {
		_, err := didWebBasic.CreateDoc(crypto.P256, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not construct verification method for DIDWeb")
	})
}

func TestDIDWebCreateDocFileBytes(t *testing.T) {
	t.Run("Happy Path - Create DID", func(tt *testing.T) {
		pk, _, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		docBytes, err := didWebBasic.CreateDocBytes(crypto.Ed25519, pk)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, docBytes)
	})

	t.Run("Unhappy Path", func(tt *testing.T) {
		_, err := didWebBasic.CreateDocBytes("bad", nil)
		assert.Error(tt, err)
	})
}

func TestDIDWebValidate(t *testing.T) {
	t.Run("Happy Path - Validate DID", func(tt *testing.T) {
		gock.New("https://demo.ssi-sdk.com").
			Get("/.well-known/did.json").
			Reply(200).
			BodyString(`{"didDocument": {"id": "did:web:demo.ssi-sdk.com"}}`)
		defer gock.Off()

		err := didWebToBeResolved.Validate(context.Background())
		assert.NoError(tt, err)
	})

	t.Run("Unresolvable Path - Validate DID", func(tt *testing.T) {
		err := didWebNotADomain.Validate(context.Background())
		assert.Error(tt, err)
		assert.ErrorContains(tt, err, "resolving doc bytes")
		assert.ErrorContains(tt, err, "did:web: is missing the required domain")
	})
}
