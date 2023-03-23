package ion

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestResolver(t *testing.T) {
	t.Run("bad resolver", func(tt *testing.T) {
		resolver, err := NewIONResolver("badurl")
		assert.Error(tt, err)
		assert.Empty(tt, resolver)
	})

	t.Run("good resolver", func(tt *testing.T) {
		resolver, err := NewIONResolver("https://www.realurl.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)
	})

	t.Run("resolve a DID", func(tt *testing.T) {
		gock.New("https://test-ion-resolver.com").
			Get("/did:ion:test").
			Reply(200).
			BodyString(`{"id":"did:ion:test"}`)
		defer gock.Off()

		resolver, err := NewIONResolver("https://test-ion-resolver.com")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		result, err := resolver.Resolve("did:ion:test", nil)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, result)
		assert.Equal(tt, "did:ion:test", result.DIDDocument.ID)
	})
}
