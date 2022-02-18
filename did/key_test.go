package did

import (
	"testing"

	"github.com/TBD54566975/did-sdk/util"

	"github.com/stretchr/testify/assert"
)

func TestCreateDIDKey(t *testing.T) {
	pk, sk, err := util.GenerateEd25519Key()
	assert.NoError(t, err)
	assert.NotEmpty(t, pk)
	assert.NotEmpty(t, sk)

	didKey, err := CreateDIDKey(pk)
	assert.NoError(t, err)
	assert.NotEmpty(t, didKey)
}
