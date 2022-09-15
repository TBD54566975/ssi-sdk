package did

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDID(t *testing.T) {
	// good did
	didKey := DIDKey("did:key:abcd")
	parsed, err := ParseDID(didKey, DIDKeyPrefix)
	assert.NoError(t, err)
	assert.NotEmpty(t, parsed)

	// bad did
	badDIDKey := DIDKey("bad")
	_, err = ParseDID(badDIDKey, DIDKeyPrefix)
	assert.Error(t, err)
}
