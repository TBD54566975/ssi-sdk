package key

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/did/resolver"
)

var mockPubKeys = []string{
	"b9c5714089478a327f09197987f16f9e5d936e8a", "5f246d7d19aa612d6718d27c1da1ee66859586b0", "7d2d43e63666f45b40316b44212325625dbaeb40", "1c1f02f1640e52b313f2d504b3c0c7ee8ad61108", "69c5888ecd21287fbdac5a43d1558bf73c51e38b",
}

func FuzzCreateAndDecode(f *testing.F) {
	keytypes := GetSupportedDIDKeyTypes()
	ktLen := len(keytypes)

	for i, pk := range mockPubKeys {
		f.Add(i, []byte(pk))
	}
	f.Fuzz(func(t *testing.T, ktSeed int, pubKey []byte) {
		kt := keytypes[(ktSeed%ktLen+ktLen)%ktLen]

		didKey, err := CreateDIDKey(kt, pubKey)
		assert.NoError(t, err)

		recvPubKey, _, _, err := didKey.Decode()
		assert.NoError(t, err)
		assert.Equal(t, pubKey, recvPubKey)
	})
}

func FuzzCreateAndResolve(f *testing.F) {
	keyTypes := GetSupportedDIDKeyTypes()
	ktLen := len(keyTypes)

	resolvers := []resolver.Resolver{KeyResolver{}}
	r, err := resolver.NewResolver(resolvers...)
	assert.NoError(f, err)

	for i, pk := range mockPubKeys {
		f.Add(i, []byte(pk))
	}

	f.Fuzz(func(t *testing.T, ktSeed int, pubKey []byte) {
		kt := keyTypes[(ktSeed%ktLen+ktLen)%ktLen]

		didKey, err := CreateDIDKey(kt, pubKey)
		assert.NoError(t, err)

		doc, err := r.Resolve(context.Background(), didKey.String())
		if err != nil {
			t.Skip()
		}
		assert.NotEmpty(t, doc)
		assert.Equal(t, didKey.String(), doc.Document.ID)
	})
}
