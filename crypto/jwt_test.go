package crypto

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJsonWebSignature2020TestVectorJWT(t *testing.T) {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	signer := getTestVectorKey0Signer(t)
	verifier, err := signer.ToVerifier()
	assert.NoError(t, err)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/implementations/spruce/credential-0--key-0-ed25519.vc-jwt.json
	credential0 := "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZToxMjMiLCJuYmYiOjE2MDk1MjkwMDQuMCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7fSwiaXNzdWVyIjoiZGlkOmV4YW1wbGU6MTIzIiwiaXNzdWFuY2VEYXRlIjoiMjAyMS0wMS0wMVQxOToyMzoyNFoifX0.W-VyJ5VehqQ7-dV1U508YEaM6Sp2ahyU96YX_OuYwh3g_LzfC2fl6JFMTVqD9ih_1kf6KcqZ90zeoPX_3JN0DQ"
	err = verifier.Verify(credential0)
	assert.NoError(t, err)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/implementations/spruce/credential-1--key-0-ed25519.vc-jwt.json
	credential1 := "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMCJ9.eyJleHAiOjE5MjUwNjE4MDQuMCwiaXNzIjoiZGlkOmV4YW1wbGU6MTIzIiwibmJmIjoxNjA5NTI5MDA0LjAsInN1YiI6ImRpZDpleGFtcGxlOjQ1NiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy9zZWN1cml0eS9zdWl0ZXMvandzLTIwMjAvdjEiLHsiQHZvY2FiIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS8jIn1dLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6NDU2IiwidHlwZSI6IlBlcnNvbiJ9LCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZToxMjMiLCJpc3N1YW5jZURhdGUiOiIyMDIxLTAxLTAxVDE5OjIzOjI0WiIsImV4cGlyYXRpb25EYXRlIjoiMjAzMS0wMS0wMVQxOToyMzoyNFoifX0.RGjgs2okheX-lH4jM7QGnNFjh1NeoH5i11N_v9EIf89P-NJYPeDBy39ZCWEIRJlfNkxclR0i2Qe09x6J7xmoDw"
	err = verifier.Verify(credential1)
	assert.NoError(t, err)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/implementations/spruce/credential-2--key-0-ed25519.vc-jwt.json
	credential2 := "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZToxMjMiLCJuYmYiOjE2MDk1MjkwMDQuMCwic3ViIjoiZGlkOmV4YW1wbGU6NDU2IiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSIseyJAdm9jYWIiOiJodHRwczovL2V4YW1wbGUuY29tLyMifV0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTo0NTYifSwiaXNzdWVyIjoiZGlkOmV4YW1wbGU6MTIzIiwiaXNzdWFuY2VEYXRlIjoiMjAyMS0wMS0wMVQxOToyMzoyNFoiLCJldmlkZW5jZSI6W3siaWQiOiJodHRwczovL2V4YW1wbGUuZWR1L2V2aWRlbmNlL2YyYWVlYzk3LWZjMGQtNDJiZi04Y2E3LTA1NDgxOTJkNDIzMSIsInR5cGUiOlsiRG9jdW1lbnRWZXJpZmljYXRpb24iXSwiZXZpZGVuY2VEb2N1bWVudCI6IkRyaXZlcnNMaWNlbnNlIiwidmVyaWZpZXIiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvMTQiLCJkb2N1bWVudFByZXNlbmNlIjoiUGh5c2ljYWwiLCJzdWJqZWN0UHJlc2VuY2UiOiJQaHlzaWNhbCJ9LHsiaWQiOiJodHRwczovL2V4YW1wbGUuZWR1L2V2aWRlbmNlL2YyYWVlYzk3LWZjMGQtNDJiZi04Y2E3LTA1NDgxOTJkeHl6YWIiLCJ0eXBlIjpbIlN1cHBvcnRpbmdBY3Rpdml0eSJdLCJkb2N1bWVudFByZXNlbmNlIjoiRGlnaXRhbCIsImV2aWRlbmNlRG9jdW1lbnQiOiJGbHVpZCBEeW5hbWljcyBGb2N1cyIsInZlcmlmaWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzE0Iiwic3ViamVjdFByZXNlbmNlIjoiRGlnaXRhbCJ9XX19.ACAXl3KyPwjbm24-l-NaNUhQ2ZniSyMVoK-saGjHZiSwFEtB_tjgRCm4_HvjuJEmhbckxPECM2a1KFglTOGNDw"
	err = verifier.Verify(credential2)
	assert.NoError(t, err)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/implementations/transmute/presentation-0--key-0-ed25519.vp-jwt.json
	presentation0 := "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZToxMjMiLCJzdWIiOiJkaWQ6ZXhhbXBsZToxMjMiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvc3VpdGVzL2p3cy0yMDIwL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJob2xkZXIiOiJkaWQ6ZXhhbXBsZToxMjMifSwibm9uY2UiOiIxMjMifQ.lEOX6r0OaGbGDLwwWkhMfo5zZ6b04JMQYXU7Q1wB1LxdrZoT2Mmxn70l-WV3oG0Fg2XSShGCiWgDOSlbA8FKDA"
	err = verifier.Verify(presentation0)
	assert.NoError(t, err)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/implementations/transmute/presentation-1--key-0-ed25519.vp-jwt.json
	presentation1 := "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZToxMjMiLCJzdWIiOiJkaWQ6ZXhhbXBsZToxMjMiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvc3VpdGVzL2p3cy0yMDIwL3YxIl0sImlkIjoidXJuOnV1aWQ6Nzg5IiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sImhvbGRlciI6ImRpZDpleGFtcGxlOjEyMyIsInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvc3VpdGVzL2p3cy0yMDIwL3YxIix7IkB2b2NhYiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vIyJ9XSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZToxMjMiLCJpc3N1YW5jZURhdGUiOiIyMDIxLTAxLTAxVDE5OjIzOjI0WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV4YW1wbGU6NDU2In0sImV2aWRlbmNlIjpbeyJpZCI6Imh0dHBzOi8vZXhhbXBsZS5lZHUvZXZpZGVuY2UvZjJhZWVjOTctZmMwZC00MmJmLThjYTctMDU0ODE5MmQ0MjMxIiwidHlwZSI6WyJEb2N1bWVudFZlcmlmaWNhdGlvbiJdLCJ2ZXJpZmllciI6Imh0dHBzOi8vZXhhbXBsZS5lZHUvaXNzdWVycy8xNCIsImV2aWRlbmNlRG9jdW1lbnQiOiJEcml2ZXJzTGljZW5zZSIsInN1YmplY3RQcmVzZW5jZSI6IlBoeXNpY2FsIiwiZG9jdW1lbnRQcmVzZW5jZSI6IlBoeXNpY2FsIn0seyJpZCI6Imh0dHBzOi8vZXhhbXBsZS5lZHUvZXZpZGVuY2UvZjJhZWVjOTctZmMwZC00MmJmLThjYTctMDU0ODE5MmR4eXphYiIsInR5cGUiOlsiU3VwcG9ydGluZ0FjdGl2aXR5Il0sInZlcmlmaWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzE0IiwiZXZpZGVuY2VEb2N1bWVudCI6IkZsdWlkIER5bmFtaWNzIEZvY3VzIiwic3ViamVjdFByZXNlbmNlIjoiRGlnaXRhbCIsImRvY3VtZW50UHJlc2VuY2UiOiJEaWdpdGFsIn1dLCJwcm9vZiI6eyJ0eXBlIjoiSnNvbldlYlNpZ25hdHVyZTIwMjAiLCJjcmVhdGVkIjoiMjAyMS0xMC0wMlQxNzo1ODowMFoiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZXhhbXBsZToxMjMja2V5LTAiLCJqd3MiOiJleUppTmpRaU9tWmhiSE5sTENKamNtbDBJanBiSW1JMk5DSmRMQ0poYkdjaU9pSkZaRVJUUVNKOS4uVkE4VlFxQWVyVVQ2QUlWZEhjOFc4UTJhajEyTE9RalZfVloxZTEzNE5VOVEyMGVCc055U1BqTmRtVFdwMkhrZHF1Q25iUmhCSHhJYk5lRkVJT09oQWcifX1dfSwibm9uY2UiOiIxMjMifQ.c_t34aU86bZBqyWH3_mkvuOwKFQA07FBmwUtctY8DT8IjRWuRKJOSLcPmyVJux_wBMbuogkVyBWeD6wixcJEBQ"
	err = verifier.Verify(presentation1)
	assert.NoError(t, err)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/implementations/transmute/presentation-2--key-0-ed25519.vp-jwt.json
	presentation2 := "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZToxMjMiLCJzdWIiOiJkaWQ6ZXhhbXBsZToxMjMiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvc3VpdGVzL2p3cy0yMDIwL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uL3ByZXNlbnRhdGlvbi1leGNoYW5nZS9zdWJtaXNzaW9uL3YxIl0sImlkIjoidXJuOnV1aWQ6Nzg5IiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwiUHJlc2VudGF0aW9uU3VibWlzc2lvbiJdLCJob2xkZXIiOiJkaWQ6ZXhhbXBsZToxMjMiLCJwcmVzZW50YXRpb25fc3VibWlzc2lvbiI6eyJpZCI6ImEzMGUzYjkxLWZiNzctNGQyMi05NWZhLTg3MTY4OWMzMjJlMiIsImRlZmluaXRpb25faWQiOiIzMmY1NDE2My03MTY2LTQ4ZjEtOTNkOC1mZjIxN2JkYjA2NTMiLCJkZXNjcmlwdG9yX21hcCI6W3siaWQiOiJleGFtcGxlX2lucHV0XzEiLCJmb3JtYXQiOiJsZHBfdmMiLCJwYXRoIjoiJC52ZXJpZmlhYmxlQ3JlZGVudGlhbFswXSJ9XX0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvc3VpdGVzL2p3cy0yMDIwL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmV4YW1wbGU6MTIzIiwiaXNzdWFuY2VEYXRlIjoiMjAyMS0wMS0wMVQxOToyMzoyNFoiLCJjcmVkZW50aWFsU3ViamVjdCI6e30sInByb29mIjp7InR5cGUiOiJKc29uV2ViU2lnbmF0dXJlMjAyMCIsImNyZWF0ZWQiOiIyMDIxLTExLTA2VDE2OjQ5OjUwWiIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMCIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCIsImp3cyI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW1JMk5DSTZabUZzYzJVc0ltTnlhWFFpT2xzaVlqWTBJbDE5Li4tT003UF8xQVhUcUMycDhiNWJlak9id1A3cmMtcElGSDV2YkJKQ1V6TFhBcVNYdFRfbVBXMHdKSUVneUVQNEFJSV9CeWd4ZWZvQV9fZXp0d0p1NGZEdyJ9fV19LCJub25jZSI6IjEyMyJ9.px35BEehXQjsmBWOKx1Q4HvaoPemH-gZlI_2tu3Pd1h27ze9YBK6gtSPJp6iWZKXKUjinl1gr9tYHpBIYJFTBw"
	err = verifier.Verify(presentation2)
	assert.NoError(t, err)
}

func TestSignVerifyJWTForEachSupportedKeyType(t *testing.T) {
	testKID := "test-kid"
	testData := map[string]any{
		"test": "data",
	}

	tests := []struct {
		kt KeyType
	}{
		{
			kt: Ed25519,
		},
		{
			kt: SECP256k1,
		},
		{
			kt: P256,
		},
		{
			kt: P384,
		},
		{
			kt: P521,
		},
		{
			kt: RSA,
		},
	}
	for _, test := range tests {
		t.Run(string(test.kt), func(t *testing.T) {
			// generate a new key based on the given key type
			pubKey, privKey, err := GenerateKeyByKeyType(test.kt)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKey)

			// create key access with the key
			signer, err := NewJWTSigner(testKID, privKey)
			assert.NoError(t, err)
			assert.NotEmpty(t, signer)

			// sign
			token, err := signer.SignWithDefaults(testData)
			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			// verify
			verifier, err := signer.ToVerifier()
			assert.NoError(t, err)
			assert.NotEmpty(t, verifier)

			sameVerifier, err := NewJWTVerifier(testKID, pubKey)
			assert.NoError(t, err)
			assert.Equal(t, verifier, sameVerifier)

			err = verifier.Verify(string(token))
			assert.NoError(t, err)
		})
	}
}

func TestSignVerifyGenericJWT(t *testing.T) {
	signer := getTestVectorKey0Signer(t)
	verifier, err := signer.ToVerifier()
	assert.NoError(t, err)

	jwtData := map[string]any{
		"id":   "abcd",
		"jti":  "1234",
		"data": []any{"one", "two", "three"},
		"more_data": map[string]int{
			"a": 1,
			"b": 2,
			"c": 3,
		},
	}
	token, err := signer.SignWithDefaults(jwtData)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	signerParsed, err := signer.Parse(string(token))
	assert.NoError(t, err)

	gotSignerID, ok := signerParsed.Get("id")
	assert.True(t, ok)
	assert.EqualValues(t, "abcd", gotSignerID)

	err = verifier.Verify(string(token))
	assert.NoError(t, err)

	parsed, err := verifier.Parse(string(token))
	assert.NoError(t, err)

	gotID, ok := parsed.Get("id")
	assert.True(t, ok)
	assert.EqualValues(t, "abcd", gotID)

	gotJTI, ok := parsed.Get(jwt.JwtIDKey)
	assert.True(t, ok)
	assert.EqualValues(t, "1234", gotJTI)

	gotData, ok := parsed.Get("data")
	assert.True(t, ok)
	assert.EqualValues(t, []any{"one", "two", "three"}, gotData)

	_, err = verifier.VerifyAndParse(string(token))
	assert.NoError(t, err)

	// parse out the headers
	jws, err := verifier.ParseJWS(string(token))
	assert.NoError(t, err)
	assert.NotEmpty(t, jws)
	assert.EqualValues(t, "EdDSA", jws.ProtectedHeaders().Algorithm())
	assert.EqualValues(t, "did:example:123#key-0", jws.ProtectedHeaders().KeyID())
}

func getTestVectorKey0Signer(t *testing.T) JWTSigner {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	knownJWK := PrivateKeyJWK{
		KID: "did:example:123#key-0",
		KTY: "OKP",
		CRV: "Ed25519",
		X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
		D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
	}

	signer, err := NewJWTSignerFromJWK(knownJWK.KID, knownJWK)
	assert.NoError(t, err)
	return *signer
}
