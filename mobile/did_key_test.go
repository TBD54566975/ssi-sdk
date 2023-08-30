package mobile

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestGetSupportedKeyTypes(t *testing.T) {
	supportedKeyTypes := GetSupportedKeyTypes()
	assert.NotEmpty(t, supportedKeyTypes)
	assert.Equal(t, len(key.GetSupportedDIDKeyTypes()), len(supportedKeyTypes))
}

func TestGenerateDIDKey(t *testing.T) {
	supportedKeyTypes := GetSupportedKeyTypes()
	assert.NotEmpty(t, supportedKeyTypes)

	for _, kt := range supportedKeyTypes {
		result, err := GenerateDIDKey(kt)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)

		var didKeyResult GenerateDIDKeyResult
		err = json.Unmarshal(result, &didKeyResult)
		assert.NoError(t, err)
		assert.NotEmpty(t, didKeyResult.DID)
		assert.NotEmpty(t, didKeyResult.JWK)
	}
}

func TestCreateDIDKey(t *testing.T) {
	supportedKeyTypes := GetSupportedKeyTypes()
	assert.NotEmpty(t, supportedKeyTypes)

	didKeys := make(map[string]GenerateDIDKeyResult)
	for _, kt := range supportedKeyTypes {
		result, err := GenerateDIDKey(kt)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)

		var didKeyResult GenerateDIDKeyResult
		err = json.Unmarshal(result, &didKeyResult)
		assert.NoError(t, err)
		assert.NotEmpty(t, didKeyResult.DID)
		assert.NotEmpty(t, didKeyResult.JWK)
		didKeys[kt] = didKeyResult
	}

	for kt, didKey := range didKeys {
		createDIDKeyRequest := CreateDIDKeyRequest{
			KeyType:      kt,
			PublicKeyJWK: didKey.JWK,
		}
		reqBytes, err := json.Marshal(createDIDKeyRequest)
		assert.NoError(t, err)
		assert.NotEmpty(t, reqBytes)

		result, err := CreateDIDKey(reqBytes)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)

		var createDIDKeyResult CreateDIDKeyResult
		err = json.Unmarshal(result, &createDIDKeyResult)
		assert.NoError(t, err)

		assert.NotEmpty(t, createDIDKeyResult.DID)
		assert.Equal(t, didKey.DID, createDIDKeyResult.DID)
	}
}
