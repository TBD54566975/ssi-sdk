package jwk

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/did/resolver"
)

func TestGenerateAndResolveDIDJWK(t *testing.T) {
	resolvers := []resolver.Resolver{Resolver{}}
	r, _ := resolver.NewResolver(resolvers...)

	for _, kt := range GetSupportedDIDJWKTypes() {
		_, didJWK, err := GenerateDIDJWK(kt)
		assert.NoError(t, err)

		doc, err := r.Resolve(context.Background(), didJWK.String())
		assert.NoError(t, err)
		assert.NotEmpty(t, doc)
		assert.Equal(t, didJWK.String(), doc.Document.ID)
	}
}
