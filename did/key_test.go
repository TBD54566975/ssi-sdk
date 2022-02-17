package did

import (
	"testing"

	"github.com/TBD54566975/did-sdk/util"

	"github.com/ockam-network/did"
	"github.com/stretchr/testify/assert"
	"github.com/textileio/go-did-resolver/keys"
)

func TestCreateDIDKey(t *testing.T) {
	pk, sk, err := util.GenerateEd25519Key()
	assert.NoError(t, err)
	assert.NotEmpty(t, pk)
	assert.NotEmpty(t, sk)

	didKey, err := CreateDIDKey(pk)
	assert.NoError(t, err)
	assert.NotEmpty(t, didKey)

	didDoc, err := did.Parse(*didKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, didDoc)
	assert.Equal(t, "key", didDoc.Method)

	document, err := keys.ExpandEd25519Key(pk, didDoc.ID)
	assert.NoError(t, err)
	assert.NotEmpty(t, document)
	assert.Equal(t, *didKey, document.ID)
	assert.Equal(t, 1, len(document.VerificationMethod))
	assert.Equal(t, "X25519KeyAgreementKey2019", document.VerificationMethod[0].Type)
	assert.Equal(t, *didKey, document.VerificationMethod[0].Controller)
}
