package resolution

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDIDDocumentMetadata_IsValid(t *testing.T) {
	t.Run("returns true with empty", func(t *testing.T) {
		var metadata DocumentMetadata
		assert.True(t, metadata.IsValid())
	})

	t.Run("test valid time", func(t *testing.T) {
		now := time.Now().UTC().Format(time.RFC3339)
		var metadata = DocumentMetadata{
			Created: now,
		}
		assert.True(t, metadata.IsValid())
	})

	t.Run("returns false when created field is not a timestamp", func(t *testing.T) {
		badMetadata := DocumentMetadata{
			Created: "bad",
			Updated: time.Now().UTC().Format(time.RFC3339),
		}
		assert.False(t, badMetadata.IsValid())
	})
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
