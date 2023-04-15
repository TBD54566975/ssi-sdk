package credential

import (
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCredentialSignature(_ *testing.T) {
	// TODO(gabe) implement this test
}

func TestVerifyJWTCredential(t *testing.T) {
	t.Run("empty credential", func(tt *testing.T) {
		_, err := VerifyJWTCredential("", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential cannot be empty")
	})

	t.Run("empty resolver", func(tt *testing.T) {
		_, err := VerifyJWTCredential("not-empty", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "resolver cannot be empty")
	})

	t.Run("invalid credential", func(tt *testing.T) {
		resolver, err := did.NewResolver([]did.Resolver{did.KeyResolver{}}...)
		assert.NoError(tt, err)
		_, err = VerifyJWTCredential("not-empty", resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid JWT")
	})

	t.Run("valid credential, not signed by DID", func(tt *testing.T) {
		resolver, err := did.NewResolver([]did.Resolver{did.KeyResolver{}}...)
		assert.NoError(tt, err)

		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		signer, err := crypto.NewJWTSigner("test-id", "test-kid", privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "error getting issuer DID<test-id> to verify credential")
	})

	t.Run("valid credential, signed by DID the resolver can't resolve", func(tt *testing.T) {
		resolver, err := did.NewResolver([]did.Resolver{did.WebResolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := did.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := crypto.NewJWTSigner(didKey.String(), kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported method: key")
	})

	t.Run("valid credential, kid not found", func(tt *testing.T) {
		resolver, err := did.NewResolver([]did.Resolver{did.KeyResolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := did.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		signer, err := crypto.NewJWTSigner(didKey.String(), "missing", privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "has no verification methods with kid: missing")
	})

	t.Run("valid credential, bad signature", func(tt *testing.T) {
		resolver, err := did.NewResolver([]did.Resolver{did.KeyResolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := did.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := crypto.NewJWTSigner(didKey.String(), kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)

		// modify the signature to make it invalid
		jwtCred = jwtCred[:len(jwtCred)-1] + "a"

		verified, err := VerifyJWTCredential(jwtCred, resolver)
		assert.Error(tt, err)
		assert.False(tt, verified)
	})

	t.Run("valid credential", func(tt *testing.T) {
		resolver, err := did.NewResolver([]did.Resolver{did.KeyResolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := did.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := crypto.NewJWTSigner(didKey.String(), kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		verified, err := VerifyJWTCredential(jwtCred, resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})
}

func getTestJWTCredential(t *testing.T, signer crypto.JWTSigner) string {
	cred := VerifiableCredential{
		ID:           uuid.NewString(),
		Context:      []any{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       signer.ID,
		IssuanceDate: time.Now().Format(time.RFC3339),
		CredentialSubject: map[string]any{
			"id":            "did:example:123",
			"favoriteColor": "green",
			"favoriteFood":  "pizza",
		},
	}

	signed, err := SignVerifiableCredentialJWT(signer, cred)
	require.NoError(t, err)
	require.NotEmpty(t, signed)
	return string(signed)
}
