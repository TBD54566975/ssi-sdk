package did

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
)

func TestEncodePublicKeyWithKeyMultiCodecType(t *testing.T) {
	// unsupported type
	_, err := encodePublicKeyWithKeyMultiCodecType(crypto.KeyType("unsupported"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a supported key type")

	// bad public key
	_, err = encodePublicKeyWithKeyMultiCodecType(crypto.Ed25519, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown public key type; could not convert to bytes")
}
