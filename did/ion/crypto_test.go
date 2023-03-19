package ion

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestBTCSigner(t *testing.T) {
	privateKeyJWKJSON, err := getTestData("jwkes256k1private.json")
	assert.NoError(t, err)
	var privateKeyJWK crypto.PrivateKeyJWK
	err = json.Unmarshal([]byte(privateKeyJWKJSON), &privateKeyJWK)
	assert.NoError(t, err)

	signer, err := NewBTCSigner(privateKeyJWK)
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	signature := signer.Sign([]byte("test"))
	assert.NotEmpty(t, signature)

	verified, err := signer.Verify([]byte("test"), signature)
	assert.NoError(t, err)
	assert.True(t, verified)
}
