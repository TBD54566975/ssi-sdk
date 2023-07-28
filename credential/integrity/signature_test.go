package integrity

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/did/ion"
	"github.com/goccy/go-json"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
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

	t.Run("empty resolution", func(tt *testing.T) {
		_, err := VerifyCredentialSignature(context.Background(), "not-empty", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "resolution cannot be empty")
	})

	t.Run("invalid credential type - int", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, err = VerifyCredentialSignature(context.Background(), 5, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid credential type: int")
	})

	t.Run("empty map credential type", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, err = VerifyCredentialSignature(context.Background(), map[string]any{"a": "test"}, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "map is not a valid credential")
	})

	t.Run("data integrity map credential type missing proof", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		cred := getTestCredential()
		_, err = VerifyCredentialSignature(context.Background(), cred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
	})

	t.Run("data integrity credential - no proof", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		cred := getTestCredential()
		_, err = VerifyCredentialSignature(context.Background(), cred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")

		// test with a pointer
		_, err = VerifyCredentialSignature(context.Background(), &cred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
	})

	t.Run("data integrity credential - as bytes and string", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		testCred := getTestCredential()
		credBytes, err := json.Marshal(testCred)
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
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
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
		_, err := VerifyJWTCredential(context.Background(), "", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential cannot be empty")
	})

	t.Run("empty resolution", func(tt *testing.T) {
		_, err := VerifyJWTCredential(context.Background(), "not-empty", nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "resolution cannot be empty")
	})

	t.Run("invalid credential", func(tt *testing.T) {
		r, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		_, err = VerifyJWTCredential(context.Background(), "not-empty", r)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid JWT")
	})

	t.Run("valid credential, not signed by DID", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		signer, err := jwx.NewJWXSigner("test-id", "test-kid", privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "error getting issuer DID<test-id> to verify credential")
	})

	t.Run("valid credential, signed by DID the resolution can't resolve", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{web.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported method: key")
	})

	t.Run("valid credential, kid not found", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		signer, err := jwx.NewJWXSigner(didKey.String(), "missing", privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		_, err = VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "has no verification methods with kid: missing")
	})

	t.Run("valid credential, bad signature", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
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

		verified, err := VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.Error(tt, err)
		assert.False(tt, verified)
	})

	t.Run("valid credential", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		privKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		signer, err := jwx.NewJWXSigner(didKey.String(), kid, privKey)
		assert.NoError(tt, err)

		jwtCred := getTestJWTCredential(tt, *signer)
		verified, err := VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})

	t.Run("valid credential with long form ion did", func(t *testing.T) {
		resolver, err := ion.NewIONResolver(http.DefaultClient, "https://ion.example.com")
		assert.NoError(t, err)
		const jwtCred = `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpQmp6ZUtpVzdXU3lqRUdtai1Jc3NlZDVoTWVmbU0yX0h3eWJLN2RTckRfWEE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZGZNalF6T0dOaU1tUWlMQ0p3ZFdKc2FXTkxaWGxLZDJzaU9uc2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVZFUkdVbWxPVTNkR2NHMTBjVFZYWDNrNVJIaG9NRGgwWlVKNlNGWkxWemxEYW5kMVJIUjVObGxKVlNJc0lua2lPaUpmVjNjMWNEUldjRVJvYkRGMmFVNUplVXRmTTFkVmJqVmlkSEowT0dWcmVqWm5OMHBIV1VaVVVVWTRJbjBzSW5CMWNuQnZjMlZ6SWpwYkltRjFkR2hsYm5ScFkyRjBhVzl1SWl3aVlYTnpaWEowYVc5dVRXVjBhRzlrSWwwc0luUjVjR1VpT2lKRlkyUnpZVk5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGtpZlYwc0luTmxjblpwWTJWeklqcGJleUpwWkNJNklteHBibXRsWkdSdmJXRnBibk1pTENKelpYSjJhV05sUlc1a2NHOXBiblFpT25zaWIzSnBaMmx1Y3lJNld5Sm9kSFJ3Y3pvdkwyeHBibXRsWkdsdUxtTnZiUzhpWFgwc0luUjVjR1VpT2lKTWFXNXJaV1JFYjIxaGFXNXpJbjBzZXlKcFpDSTZJbWgxWWlJc0luTmxjblpwWTJWRmJtUndiMmx1ZENJNmV5SnBibk4wWVc1alpYTWlPbHNpYUhSMGNITTZMeTlpWlhSaExtaDFZaTV0YzJsa1pXNTBhWFI1TG1OdmJTOTJNUzR3THpVNE9XUTFNMkkxTFdSbFpqVXROREl6TlMxaU5qUXlMVGhsTVdNME1XVTRZbU5oTVNKZGZTd2lkSGx3WlNJNklrbGtaVzUwYVhSNVNIVmlJbjFkZlgxZExDSjFjR1JoZEdWRGIyMXRhWFJ0Wlc1MElqb2lSV2xCYlRVdGFFNXRWbmhTVVZkT1ptMTNRelpXTVRaaE4wYzNTbTVyVHpNNGFVZFVVRlkyTjNGNFEzTkRkeUo5TENKemRXWm1hWGhFWVhSaElqcDdJbVJsYkhSaFNHRnphQ0k2SWtWcFFqRlBRa2huYWt0amFrcGtMVkZRZWkxUllXWlFibGRCZW1SdWNtaDVXVkIyVUVsZlZuSnpUbTVYZDBFaUxDSnlaV052ZG1WeWVVTnZiVzFwZEcxbGJuUWlPaUpGYVVNMk5uTllTR1ZHTWtseWRuaElTM3BDY1dWRVRHd3pWRU5TUzJwVlpFSnNkbVJmYmtaS01GcDNZVFJuSW4xOSNzaWdfMjQzOGNiMmQifQ.eyJzdWIiOiJkaWQ6aW9uOkVpQmp6ZUtpVzdXU3lqRUdtai1Jc3NlZDVoTWVmbU0yX0h3eWJLN2RTckRfWEE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZGZNalF6T0dOaU1tUWlMQ0p3ZFdKc2FXTkxaWGxLZDJzaU9uc2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVZFUkdVbWxPVTNkR2NHMTBjVFZYWDNrNVJIaG9NRGgwWlVKNlNGWkxWemxEYW5kMVJIUjVObGxKVlNJc0lua2lPaUpmVjNjMWNEUldjRVJvYkRGMmFVNUplVXRmTTFkVmJqVmlkSEowT0dWcmVqWm5OMHBIV1VaVVVVWTRJbjBzSW5CMWNuQnZjMlZ6SWpwYkltRjFkR2hsYm5ScFkyRjBhVzl1SWl3aVlYTnpaWEowYVc5dVRXVjBhRzlrSWwwc0luUjVjR1VpT2lKRlkyUnpZVk5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGtpZlYwc0luTmxjblpwWTJWeklqcGJleUpwWkNJNklteHBibXRsWkdSdmJXRnBibk1pTENKelpYSjJhV05sUlc1a2NHOXBiblFpT25zaWIzSnBaMmx1Y3lJNld5Sm9kSFJ3Y3pvdkwyeHBibXRsWkdsdUxtTnZiUzhpWFgwc0luUjVjR1VpT2lKTWFXNXJaV1JFYjIxaGFXNXpJbjBzZXlKcFpDSTZJbWgxWWlJc0luTmxjblpwWTJWRmJtUndiMmx1ZENJNmV5SnBibk4wWVc1alpYTWlPbHNpYUhSMGNITTZMeTlpWlhSaExtaDFZaTV0YzJsa1pXNTBhWFI1TG1OdmJTOTJNUzR3THpVNE9XUTFNMkkxTFdSbFpqVXROREl6TlMxaU5qUXlMVGhsTVdNME1XVTRZbU5oTVNKZGZTd2lkSGx3WlNJNklrbGtaVzUwYVhSNVNIVmlJbjFkZlgxZExDSjFjR1JoZEdWRGIyMXRhWFJ0Wlc1MElqb2lSV2xCYlRVdGFFNXRWbmhTVVZkT1ptMTNRelpXTVRaaE4wYzNTbTVyVHpNNGFVZFVVRlkyTjNGNFEzTkRkeUo5TENKemRXWm1hWGhFWVhSaElqcDdJbVJsYkhSaFNHRnphQ0k2SWtWcFFqRlBRa2huYWt0amFrcGtMVkZRZWkxUllXWlFibGRCZW1SdWNtaDVXVkIyVUVsZlZuSnpUbTVYZDBFaUxDSnlaV052ZG1WeWVVTnZiVzFwZEcxbGJuUWlPaUpGYVVNMk5uTllTR1ZHTWtseWRuaElTM3BDY1dWRVRHd3pWRU5TUzJwVlpFSnNkbVJmYmtaS01GcDNZVFJuSW4xOSIsImlzcyI6ImRpZDppb246RWlCanplS2lXN1dTeWpFR21qLUlzc2VkNWhNZWZtTTJfSHd5Yks3ZFNyRF9YQTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp6YVdkZk1qUXpPR05pTW1RaUxDSndkV0pzYVdOTFpYbEtkMnNpT25zaVkzSjJJam9pYzJWamNESTFObXN4SWl3aWEzUjVJam9pUlVNaUxDSjRJam9pVkVSR1VtbE9VM2RHY0cxMGNUVlhYM2s1Ukhob01EaDBaVUo2U0ZaTFZ6bERhbmQxUkhSNU5sbEpWU0lzSW5raU9pSmZWM2MxY0RSV2NFUm9iREYyYVU1SmVVdGZNMWRWYmpWaWRISjBPR1ZyZWpabk4wcEhXVVpVVVVZNEluMHNJbkIxY25CdmMyVnpJanBiSW1GMWRHaGxiblJwWTJGMGFXOXVJaXdpWVhOelpYSjBhVzl1VFdWMGFHOWtJbDBzSW5SNWNHVWlPaUpGWTJSellWTmxZM0F5TlRack1WWmxjbWxtYVdOaGRHbHZia3RsZVRJd01Ua2lmVjBzSW5ObGNuWnBZMlZ6SWpwYmV5SnBaQ0k2SW14cGJtdGxaR1J2YldGcGJuTWlMQ0p6WlhKMmFXTmxSVzVrY0c5cGJuUWlPbnNpYjNKcFoybHVjeUk2V3lKb2RIUndjem92TDJ4cGJtdGxaR2x1TG1OdmJTOGlYWDBzSW5SNWNHVWlPaUpNYVc1clpXUkViMjFoYVc1ekluMHNleUpwWkNJNkltaDFZaUlzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2ZXlKcGJuTjBZVzVqWlhNaU9sc2lhSFIwY0hNNkx5OWlaWFJoTG1oMVlpNXRjMmxrWlc1MGFYUjVMbU52YlM5Mk1TNHdMelU0T1dRMU0ySTFMV1JsWmpVdE5ESXpOUzFpTmpReUxUaGxNV00wTVdVNFltTmhNU0pkZlN3aWRIbHdaU0k2SWtsa1pXNTBhWFI1U0hWaUluMWRmWDFkTENKMWNHUmhkR1ZEYjIxdGFYUnRaVzUwSWpvaVJXbEJiVFV0YUU1dFZuaFNVVmRPWm0xM1F6WldNVFpoTjBjM1NtNXJUek00YVVkVVVGWTJOM0Y0UTNORGR5SjlMQ0p6ZFdabWFYaEVZWFJoSWpwN0ltUmxiSFJoU0dGemFDSTZJa1ZwUWpGUFFraG5ha3RqYWtwa0xWRlFlaTFSWVdaUWJsZEJlbVJ1Y21oNVdWQjJVRWxmVm5KelRtNVhkMEVpTENKeVpXTnZkbVZ5ZVVOdmJXMXBkRzFsYm5RaU9pSkZhVU0yTm5OWVNHVkdNa2x5ZG5oSVMzcENjV1ZFVEd3elZFTlNTMnBWWkVKc2RtUmZia1pLTUZwM1lUUm5JbjE5IiwibmJmIjoxNjQ5Mjg2NzM3LCJleHAiOjI0MzgyMDUxMzcsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2NvbnRleHRzL2RpZC1jb25maWd1cmF0aW9uLXYwLjAuanNvbmxkIl0sImlzc3VlciI6ImRpZDppb246RWlCanplS2lXN1dTeWpFR21qLUlzc2VkNWhNZWZtTTJfSHd5Yks3ZFNyRF9YQTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUp6YVdkZk1qUXpPR05pTW1RaUxDSndkV0pzYVdOTFpYbEtkMnNpT25zaVkzSjJJam9pYzJWamNESTFObXN4SWl3aWEzUjVJam9pUlVNaUxDSjRJam9pVkVSR1VtbE9VM2RHY0cxMGNUVlhYM2s1Ukhob01EaDBaVUo2U0ZaTFZ6bERhbmQxUkhSNU5sbEpWU0lzSW5raU9pSmZWM2MxY0RSV2NFUm9iREYyYVU1SmVVdGZNMWRWYmpWaWRISjBPR1ZyZWpabk4wcEhXVVpVVVVZNEluMHNJbkIxY25CdmMyVnpJanBiSW1GMWRHaGxiblJwWTJGMGFXOXVJaXdpWVhOelpYSjBhVzl1VFdWMGFHOWtJbDBzSW5SNWNHVWlPaUpGWTJSellWTmxZM0F5TlRack1WWmxjbWxtYVdOaGRHbHZia3RsZVRJd01Ua2lmVjBzSW5ObGNuWnBZMlZ6SWpwYmV5SnBaQ0k2SW14cGJtdGxaR1J2YldGcGJuTWlMQ0p6WlhKMmFXTmxSVzVrY0c5cGJuUWlPbnNpYjNKcFoybHVjeUk2V3lKb2RIUndjem92TDJ4cGJtdGxaR2x1TG1OdmJTOGlYWDBzSW5SNWNHVWlPaUpNYVc1clpXUkViMjFoYVc1ekluMHNleUpwWkNJNkltaDFZaUlzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2ZXlKcGJuTjBZVzVqWlhNaU9sc2lhSFIwY0hNNkx5OWlaWFJoTG1oMVlpNXRjMmxrWlc1MGFYUjVMbU52YlM5Mk1TNHdMelU0T1dRMU0ySTFMV1JsWmpVdE5ESXpOUzFpTmpReUxUaGxNV00wTVdVNFltTmhNU0pkZlN3aWRIbHdaU0k2SWtsa1pXNTBhWFI1U0hWaUluMWRmWDFkTENKMWNHUmhkR1ZEYjIxdGFYUnRaVzUwSWpvaVJXbEJiVFV0YUU1dFZuaFNVVmRPWm0xM1F6WldNVFpoTjBjM1NtNXJUek00YVVkVVVGWTJOM0Y0UTNORGR5SjlMQ0p6ZFdabWFYaEVZWFJoSWpwN0ltUmxiSFJoU0dGemFDSTZJa1ZwUWpGUFFraG5ha3RqYWtwa0xWRlFlaTFSWVdaUWJsZEJlbVJ1Y21oNVdWQjJVRWxmVm5KelRtNVhkMEVpTENKeVpXTnZkbVZ5ZVVOdmJXMXBkRzFsYm5RaU9pSkZhVU0yTm5OWVNHVkdNa2x5ZG5oSVMzcENjV1ZFVEd3elZFTlNTMnBWWkVKc2RtUmZia1pLTUZwM1lUUm5JbjE5IiwiaXNzdWFuY2VEYXRlIjoiMjAyMi0wNC0wNlQyMzoxMjoxNy44MzVaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDQ3LTA0LTA2VDIzOjEyOjE3LjgzNVoiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6aW9uOkVpQmp6ZUtpVzdXU3lqRUdtai1Jc3NlZDVoTWVmbU0yX0h3eWJLN2RTckRfWEE6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKemFXZGZNalF6T0dOaU1tUWlMQ0p3ZFdKc2FXTkxaWGxLZDJzaU9uc2lZM0oySWpvaWMyVmpjREkxTm1zeElpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVZFUkdVbWxPVTNkR2NHMTBjVFZYWDNrNVJIaG9NRGgwWlVKNlNGWkxWemxEYW5kMVJIUjVObGxKVlNJc0lua2lPaUpmVjNjMWNEUldjRVJvYkRGMmFVNUplVXRmTTFkVmJqVmlkSEowT0dWcmVqWm5OMHBIV1VaVVVVWTRJbjBzSW5CMWNuQnZjMlZ6SWpwYkltRjFkR2hsYm5ScFkyRjBhVzl1SWl3aVlYTnpaWEowYVc5dVRXVjBhRzlrSWwwc0luUjVjR1VpT2lKRlkyUnpZVk5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGtpZlYwc0luTmxjblpwWTJWeklqcGJleUpwWkNJNklteHBibXRsWkdSdmJXRnBibk1pTENKelpYSjJhV05sUlc1a2NHOXBiblFpT25zaWIzSnBaMmx1Y3lJNld5Sm9kSFJ3Y3pvdkwyeHBibXRsWkdsdUxtTnZiUzhpWFgwc0luUjVjR1VpT2lKTWFXNXJaV1JFYjIxaGFXNXpJbjBzZXlKcFpDSTZJbWgxWWlJc0luTmxjblpwWTJWRmJtUndiMmx1ZENJNmV5SnBibk4wWVc1alpYTWlPbHNpYUhSMGNITTZMeTlpWlhSaExtaDFZaTV0YzJsa1pXNTBhWFI1TG1OdmJTOTJNUzR3THpVNE9XUTFNMkkxTFdSbFpqVXROREl6TlMxaU5qUXlMVGhsTVdNME1XVTRZbU5oTVNKZGZTd2lkSGx3WlNJNklrbGtaVzUwYVhSNVNIVmlJbjFkZlgxZExDSjFjR1JoZEdWRGIyMXRhWFJ0Wlc1MElqb2lSV2xCYlRVdGFFNXRWbmhTVVZkT1ptMTNRelpXTVRaaE4wYzNTbTVyVHpNNGFVZFVVRlkyTjNGNFEzTkRkeUo5TENKemRXWm1hWGhFWVhSaElqcDdJbVJsYkhSaFNHRnphQ0k2SWtWcFFqRlBRa2huYWt0amFrcGtMVkZRZWkxUllXWlFibGRCZW1SdWNtaDVXVkIyVUVsZlZuSnpUbTVYZDBFaUxDSnlaV052ZG1WeWVVTnZiVzFwZEcxbGJuUWlPaUpGYVVNMk5uTllTR1ZHTWtseWRuaElTM3BDY1dWRVRHd3pWRU5TUzJwVlpFSnNkbVJmYmtaS01GcDNZVFJuSW4xOSIsIm9yaWdpbiI6Imh0dHBzOi8vd3d3LmxpbmtlZGluLmNvbS8ifX19.oTFcVvKmYU1Mxh9Q4V5UNikddYANLjw-m3530PNDhFYmR1Dm8DOcjdU-p2rJ6vSZnUKatXV5VJLJxj1aJyuhlw`
		verified, err := VerifyJWTCredential(context.Background(), jwtCred, resolver)
		assert.NoError(t, err)
		assert.True(t, verified)
	})
}

func getTestJWTCredential(t *testing.T, signer jwx.Signer) string {
	cred := credential.VerifiableCredential{
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

func getTestCredential() credential.VerifiableCredential {
	return credential.VerifiableCredential{
		Context:           []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{},
	}
}
