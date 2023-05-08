package resolver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDIDDocumentMetadata(t *testing.T) {
	// good
	var metadata DocumentMetadata
	assert.True(t, metadata.IsValid())

	// bad
	badMetadata := DocumentMetadata{
		Created: "bad",
		Updated: time.Now().UTC().Format(time.RFC3339),
	}
	assert.False(t, badMetadata.IsValid())
}

func TestParseDIDResolution(t *testing.T) {
	t.Run("bad response", func(tt *testing.T) {
		_, err := ParseDIDResolution([]byte("bad response"))
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not parse DID Resolution Result or DID Document")
	})

	t.Run("bad did document", func(tt *testing.T) {
		resolutionResult, err := ParseDIDResolution([]byte(`{"didDocument": "bad document"}`))
		assert.Error(tt, err)
		assert.Empty(tt, resolutionResult)
		assert.Contains(tt, err.Error(), "empty DID Document")
	})

	t.Run("good response", func(tt *testing.T) {
		resolutionResult, err := ParseDIDResolution([]byte(`{"didDocument": {"id": "did:ion:test"}}`))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolutionResult)
		assert.False(tt, resolutionResult.Document.IsEmpty())
		assert.Equal(tt, "did:ion:test", resolutionResult.Document.ID)
	})
}
