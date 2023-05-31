package key

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
)

func TestResolveKeyForDID(t *testing.T) {
	r, err := resolution.NewResolver([]resolution.Resolver{Resolver{}}...)
	require.NoError(t, err)
	require.NotEmpty(t, r)

	t.Run("empty resolution", func(tt *testing.T) {
		_, err = resolution.ResolveKeyForDID(context.Background(), nil, "did:test", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "resolution cannot be empty")
	})

	t.Run("empty did", func(tt *testing.T) {
		_, err = resolution.ResolveKeyForDID(context.Background(), r, "", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "not a valid did")
	})

	t.Run("unresolveable did", func(tt *testing.T) {
		_, err = resolution.ResolveKeyForDID(context.Background(), r, "did:example:test", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported method: example")
	})

	t.Run("unresolveable did", func(tt *testing.T) {
		_, err = resolution.ResolveKeyForDID(context.Background(), r, "did:example:test", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported method: example")
	})

	t.Run("invalid did", func(tt *testing.T) {
		_, err = resolution.ResolveKeyForDID(context.Background(), r, "did:key:test", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not expand did:key DID")
	})

	t.Run("valid did; no kid", func(tt *testing.T) {
		_, didKey, err := GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		_, err = resolution.ResolveKeyForDID(context.Background(), r, didKey.String(), "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "has no validation methods with kid: test-kid")
	})

	t.Run("valid did; valid kid", func(tt *testing.T) {
		privKey, didKey, err := GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID

		key, err := resolution.ResolveKeyForDID(context.Background(), r, didKey.String(), kid)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, key)

		pubKey := privKey.(ed25519.PrivateKey).Public()
		assert.Equal(tt, pubKey, key)
	})
}
