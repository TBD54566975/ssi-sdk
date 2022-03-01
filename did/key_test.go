package did

import (
	"strings"
	"testing"

	"github.com/TBD54566975/did-sdk/crypto"

	"github.com/stretchr/testify/assert"
)

func TestCreateDIDKey(t *testing.T) {
	pk, sk, err := crypto.GenerateEd25519Key()
	assert.NoError(t, err)
	assert.NotEmpty(t, pk)
	assert.NotEmpty(t, sk)

	didKey, err := CreateDIDKey(crypto.Ed25519, pk)
	assert.NoError(t, err)
	assert.NotEmpty(t, didKey)
}

func TestGenerateDIDKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType crypto.KeyType
	}{
		{
			name:    "Ed25519",
			keyType: crypto.Ed25519,
		},
		{
			name:    "x25519",
			keyType: crypto.X25519,
		},
		{
			name:    "Secp256k1",
			keyType: crypto.Secp256k1,
		},
		{
			name:    "P256",
			keyType: crypto.P256,
		},
		{
			name:    "P384",
			keyType: crypto.P384,
		},
		{
			name:    "P521",
			keyType: crypto.P521,
		},
		{
			name:    "RSA",
			keyType: crypto.RSA,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			privKey, didKey, err := GenerateDIDKey(test.keyType)
			assert.NoError(t, err)
			assert.NotNil(t, didKey)
			assert.NotEmpty(t, privKey)
			assert.True(t, strings.Contains(string(*didKey), "did:key"))
		})
	}
}
