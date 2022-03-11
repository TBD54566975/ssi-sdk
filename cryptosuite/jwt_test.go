package cryptosuite

import (
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJsonWebSignature2020TestVectorCredential0JWT(t *testing.T) {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	_, key := getTestVectorKey0Signer(t, AssertionMethod)
	key.PublicKeyJWK.KID = key.ID
	key.PublicKeyJWK.Alg = string(jwa.EdDSA)

	pubKeyJWKBytes, err := json.Marshal(key.PublicKeyJWK)
	assert.NoError(t, err)

	pubKeyJWK, err := jwk.ParseKey(pubKeyJWKBytes)
	assert.NoError(t, err)

	set := jwk.NewSet()
	set.Add(pubKeyJWK)
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/credentials/credential-0.json
	//knownCred := TestCredential{
	//	Context:           []interface{}{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
	//	Type:              []string{"VerifiableCredential"},
	//	Issuer:            "did:example:123",
	//	IssuanceDate:      "2021-01-01T19:23:24Z",
	//	CredentialSubject: map[string]interface{}{},
	//}

	//suite := GetJSONWebSignature2020Suite()
	//err := suite.Sign(&signer, &knownCred)
	//assert.NoError(t, err)
	//
	//verifier, err := NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
	//assert.NoError(t, err)
	//
	//// first verify our credential
	//err = suite.Verify(verifier, &knownCred)
	//assert.NoError(t, err)

	jwtValue := "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZToxMjMiLCJzdWIiOiJkaWQ6ZXhhbXBsZTo0NTYiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvc3VpdGVzL2p3cy0yMDIwL3YxIix7IkB2b2NhYiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vIyJ9XSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZToxMjMiLCJpc3N1YW5jZURhdGUiOiIyMDIxLTAxLTAxVDE5OjIzOjI0WiIsImV4cGlyYXRpb25EYXRlIjoiMjAzMS0wMS0wMVQxOToyMzoyNFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpleGFtcGxlOjQ1NiIsInR5cGUiOiJQZXJzb24ifX0sIm5iZiI6MTYwOTUyOTAwNCwiZXhwIjoxOTI1MDYxODA0fQ._puMPlkpzss1AOFe0HWPnwW98lGmfE6vHsPN9ZGTEWz6PGscHpprfXUksQN63cm3dPcRxcWmtFt2QqzGn7zxBA"
	token, err := jwt.Parse([]byte(jwtValue), jwt.WithKeySet(set))
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}
