package did

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

const (
	P256Vector   string = "did-jwk-p256.json"
	X25519Vector string = "did-jwk-x25519.json"
)

var (
	//go:embed testdata
	jwkTestVectors embed.FS
	jwkVectors     = []string{P256Vector, X25519Vector}
)

// from https://github.com/quartzjer/did-jwk/blob/main/spec.md#examples
func TestDIDJWKVectors(t *testing.T) {
	t.Run("P-256", func(tt *testing.T) {
		did := "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
		didJWK := DIDJWK(did)
		valid := didJWK.IsValid()
		assert.True(tt, valid)

		gotTestVector, err := getTestVector(P256Vector)
		assert.NoError(t, err)
		var didDoc Document
		err = json.Unmarshal([]byte(gotTestVector), &didDoc)
		assert.NoError(tt, err)

		ourDID, err := didJWK.Expand()
		assert.NoError(tt, err)

		// turn into json and compare
		ourDIDJSON, err := json.Marshal(ourDID)
		assert.NoError(tt, err)
		didDocJSON, err := json.Marshal(didDoc)
		assert.NoError(tt, err)
		assert.JSONEq(tt, string(ourDIDJSON), string(didDocJSON))
	})

	t.Run("X25519", func(tt *testing.T) {
		did := "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"
		didJWK := DIDJWK(did)
		valid := didJWK.IsValid()
		assert.True(tt, valid)

		gotTestVector, err := getTestVector(X25519Vector)
		assert.NoError(t, err)
		var didDoc Document
		err = json.Unmarshal([]byte(gotTestVector), &didDoc)
		assert.NoError(tt, err)

		ourDID, err := didJWK.Expand()
		assert.NoError(tt, err)

		// turn into json and compare
		ourDIDJSON, err := json.Marshal(ourDID)
		assert.NoError(tt, err)
		didDocJSON, err := json.Marshal(didDoc)
		assert.NoError(tt, err)

		assert.JSONEq(tt, string(ourDIDJSON), string(didDocJSON))
	})
}
