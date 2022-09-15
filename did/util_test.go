package did

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestEncodePublicKeyWithKeyMultiCodecType(t *testing.T) {
	// unsupported type
	_, err := encodePublicKeyWithKeyMultiCodecType(crypto.KeyType("unsupported"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a supported key type")

	// bad public key
	_, err = encodePublicKeyWithKeyMultiCodecType(crypto.Ed25519, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown public key type; could not convert to bytes")
}

func TestResolveDID(t *testing.T) {
	// unsupported type
	_, err := ResolveDID("did:unsupported:123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported Method for DID")

	// did key
	_, didKey, err := GenerateDIDKey(crypto.Ed25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, didKey)
	doc, err := ResolveDID(didKey.ToString())
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)

	// did pkh
	address := "0xb9c5714089478a327f09197987f16f9e5d936e8a"
	didPKH, err := CreateDIDPKHFromNetwork(Ethereum, address)
	assert.NoError(t, err)
	assert.NotEmpty(t, didPKH)
	doc, err = ResolveDID(didPKH.ToString())
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)

	// did peer
	didPeer := "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	doc, err = ResolveDID(didPeer)
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)

	// did web
	gock.New("https://demo.ssi-sdk.com").
		Get("/.well-known/did.json").
		Reply(200).
		BodyString(`{"id":"did:web:demo.ssi-sdk.com"}`)
	defer gock.Off()
	didWeb := "did:web:demo.ssi-sdk.com"
	doc, err = ResolveDID(didWeb)
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)
}
