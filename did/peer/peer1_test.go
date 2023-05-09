package peer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPeerMethod1(t *testing.T) {
	var m1 Method1
	_, err := m1.Generate()
	assert.Error(t, err)
	assert.Contains(t, "not implemented", err.Error())
}
