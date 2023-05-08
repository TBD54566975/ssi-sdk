package credential

import (
	"context"
	"testing"
	"time"

	"github.com/goccy/go-json"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/did/resolver"
	"github.com/TBD54566975/ssi-sdk/did/web"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCredentialSignature(t *testing.T) {
	t.Run("empty credential", func(tt *testing.T) {
		_, err := VerifyCredentialSignature(context.Background(), nil, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential cannot be empty")
	})

	t.Run("empty resolver", func(tt *testing.T) {
		_, err := VerifyCredentialSignature(context.Background(), "not-empty", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "resolver cannot be empty")
	})

	t.Run("invalid credential type - int", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, err = VerifyCredentialSignature(context.Background(), 5, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid credential type: int")
	})

	t.Run("empty map credential type", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, err = VerifyCredentialSignature(context.Background(), map[string]any{"a": "test"}, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "converting credential from generic type: parsing generic credential as either VC or JWT")
	})

	t.Run("data integrity map credential type missing proof", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		credential := getTestCredential()
		credMap, err := ToCredentialJSONMap(credential)
		assert.NoError(tt, err)

		_, err = VerifyCredentialSignature(context.Background(), credMap, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
	})

	t.Run("data integrity credential - no proof", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		credential := getTestCredential()
		_, err = VerifyCredentialSignature(context.Background(), credential, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")

		// test with a pointer
		_, err = VerifyCredentialSignature(context.Background(), &credential, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
	})

	t.Run("data integrity credential - as bytes and string", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		credential := getTestCredential()
		credBytes, err := json.Marshal(credential)
		assert.NoError(tt, err)
		_, err = VerifyCredentialSignature(context.Background(), credBytes, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")

		// test with a string
		_, err = VerifyCredentialSignature(context.Background(), string(credBytes), resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
	})

	t.Run("jwt credential - as bytes and string", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		verified, err := VerifyCredentialSignature(context.Background(), jwtCred, resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)

		// test with bytes
		verified, err = VerifyCredentialSignature(context.Background(), []byte(jwtCred), resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})
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
		r, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		_, err = VerifyJWTCredential("not-empty", r)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid JWT")
	})

	t.Run("valid credential, not signed by DID", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		signer, err := jwx.NewJWXSigner("test-id", "test-kid", privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "error getting issuer DID<test-id> to verify credential")
	})

	t.Run("valid credential, signed by DID the resolver can't resolve", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{web.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported method: key")
	})

	t.Run("valid credential, kid not found", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		signer, err := jwx.NewJWXSigner(didKey.String(), "missing", privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "has no verification methods with kid: missing")
	})

	t.Run("valid credential, bad signature", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)

		// modify the signature to make it invalid
		jwtCred = jwtCred[:len(jwtCred)-5] + "baddata"

		verified, err := VerifyJWTCredential(jwtCred, resolver)
		assert.Error(tt, err)
		assert.False(tt, verified)
	})

	t.Run("valid credential", func(tt *testing.T) {
		resolver, err := resolver.NewResolver([]resolver.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		verified, err := VerifyJWTCredential(jwtCred, resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})
}

func getTestJWTCredential(t *testing.T, signer jwx.Signer) string {
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
