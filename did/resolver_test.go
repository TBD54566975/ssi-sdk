package did

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestResolveDID(t *testing.T) {
	resolvers := []Resolver{KeyResolver{}, WebResolver{}, PKHResolver{}, PeerResolver{}}
	resolver, err := NewResolver(resolvers...)
	assert.NoError(t, err)
	assert.NotEmpty(t, resolver)
	assert.Equal(t, len(resolvers), len(resolver.Methods()))

	// unsupported type
	_, err = resolver.Resolve(context.Background(), "did:unsupported:123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported method: unsupported")

	// did key
	_, didKey, err := GenerateDIDKey(crypto.Ed25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, didKey)
	doc, err := resolver.Resolve(context.Background(), didKey.String())
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)

	// did pkh
	address := "0xb9c5714089478a327f09197987f16f9e5d936e8a"
	didPKH, err := CreateDIDPKHFromNetwork(Ethereum, address)
	assert.NoError(t, err)
	assert.NotEmpty(t, didPKH)
	doc, err = resolver.Resolve(context.Background(), didPKH.String())
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)

	// did peer
	didPeer := "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	doc, err = resolver.Resolve(context.Background(), didPeer)
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)

	// did web
	gock.New("https://demo.ssi-sdk.com").
		Get("/.well-known/did.json").
		Reply(200).
		BodyString(`{"didDocument": {"id": "did:web:demo.ssi-sdk.com"}}`)
	defer gock.Off()
	didWeb := "did:web:demo.ssi-sdk.com"
	doc, err = resolver.Resolve(context.Background(), didWeb)
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)
}

func TestParseDIDResolution(t *testing.T) {
	t.Run("bad response", func(tt *testing.T) {
		_, err := ParseDIDResolution([]byte("bad response"))
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not parse DID Resolution Result or DID Document")
	})

	t.Run("bad did document", func(tt *testing.T) {
		resolutionResult, err := ParseDIDResolution([]byte(`{"didDocument": "bad document"}`))
		assert.Error(tt, err)
		assert.Empty(tt, resolutionResult)
		assert.Contains(tt, err.Error(), "empty DID Document")
	})

	t.Run("good response", func(tt *testing.T) {
		resolutionResult, err := ParseDIDResolution([]byte(`{"didDocument": {"id": "did:ion:test"}}`))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolutionResult)
		assert.False(tt, resolutionResult.Document.IsEmpty())
		assert.Equal(tt, "did:ion:test", resolutionResult.Document.ID)
	})
}
