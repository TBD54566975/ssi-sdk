package cryptosuite

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
func TestKnownEd25519JWK(t *testing.T) {
	// key-0-ed25519.json
	knownJWK := JSONWebKey2020{
		PublicKeyJWK: PublicKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
		},
		PrivateKeyJWK: PrivateKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
		},
	}

	decodedD, err := base64.RawURLEncoding.DecodeString(knownJWK.D)
	assert.NoError(t, err)
	decodedX, err := base64.RawURLEncoding.DecodeString(knownJWK.PrivateKeyJWK.X)
	assert.NoError(t, err)
	pkResult := append(decodedD, decodedX...)
	assert.NoError(t, err)

	// reconstruct private key
	privateKey := ed25519.PrivateKey(pkResult)
	// reconstruct pub key
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// reconstruct PublicKeyJWK
	ourJWK, err := PublicEd25519JSONWebKey2020(publicKey)
	assert.NoError(t, err)
	assert.EqualValues(t, knownJWK.PublicKeyJWK, *ourJWK)

	pkjwk, err := PrivateEd25519JSONWebKey2020(privateKey)
	assert.NoError(t, err)
	assert.EqualValues(t, knownJWK.PrivateKeyJWK, *pkjwk)
}
