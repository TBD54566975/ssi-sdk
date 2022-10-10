package did

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestResolveDID(t *testing.T) {
	resolvers := []Resolution{KeyResolver{}, WebResolver{}, PKHResolver{}, PeerResolver{}}
	resolver, err := NewResolver(resolvers...)
	assert.NoError(t, err)
	assert.NotEmpty(t, resolver)
	assert.Equal(t, len(resolvers), len(resolver.SupportedMethods()))

	// unsupported type
	_, err = resolver.Resolve("did:unsupported:123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported method: unsupported")

	// did key
	_, didKey, err := GenerateDIDKey(crypto.Ed25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, didKey)
	doc, err := resolver.Resolve(didKey.ToString())
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)

	// did pkh
	address := "0xb9c5714089478a327f09197987f16f9e5d936e8a"
	didPKH, err := CreateDIDPKHFromNetwork(Ethereum, address)
	assert.NoError(t, err)
	assert.NotEmpty(t, didPKH)
	doc, err = resolver.Resolve(didPKH.ToString())
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)

	// did peer
	didPeer := "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	doc, err = resolver.Resolve(didPeer)
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)

	// did web
	gock.New("https://demo.ssi-sdk.com").
		Get("/.well-known/did.json").
		Reply(200).
		BodyString(`{"id":"did:web:demo.ssi-sdk.com"}`)
	defer gock.Off()
	didWeb := "did:web:demo.ssi-sdk.com"
	doc, err = resolver.Resolve(didWeb)
	assert.NoError(t, err)
	assert.NotEmpty(t, doc)
}
