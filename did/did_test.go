package did

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDID(t *testing.T) {
	// good did
	didKey := DIDKey("did:key:abcd")
	parsed, err := didKey.Suffix()
	assert.NoError(t, err)
	assert.NotEmpty(t, parsed)

	// bad did
	badDIDKey := DIDKey("bad")
	_, err = badDIDKey.Suffix()
	assert.Error(t, err)
}
