package jwk

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/did/resolution"
)

func TestGenerateAndResolveDIDJWK(t *testing.T) {
	resolvers := []resolution.Resolver{Resolver{}}
	r, _ := resolution.NewResolver(resolvers...)

	for _, kt := range GetSupportedDIDJWKTypes() {
		_, didJWK, err := GenerateDIDJWK(kt)
		assert.NoError(t, err)

		doc, err := r.Resolve(context.Background(), didJWK.String())
		assert.NoError(t, err)
		assert.NotEmpty(t, doc)
		assert.Equal(t, didJWK.String(), doc.Document.ID)
	}
}
