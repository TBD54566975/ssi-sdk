package status

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitstringGeneration(t *testing.T) {
	t.Run("happy path", func(tt *testing.T) {
		credIndices := []string{"123", "112", "440185", "52058", "9999"}
		bitString, err := bitstringGeneration(credIndices)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, bitString)

		expanded, err := bitstringExpansion(bitString)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, expanded)

		assert.Equal(tt, bitString, expanded)
	})

	t.Run("no elements", func(tt *testing.T) {
		var credIndices []string
		bitString, err := bitstringGeneration(credIndices)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot create a status list bitstring with no credential indices")
		assert.Empty(tt, bitString)
	})

	t.Run("invalid elements", func(tt *testing.T) {
		credIndices := []string{"-1", "2", "3"}
		bitString, err := bitstringGeneration(credIndices)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid status list index value, not a valid positive integer: -1")
		assert.Empty(tt, bitString)
	})

	t.Run("repeated elements", func(tt *testing.T) {
		credIndices := []string{"2", "2", "3"}
		bitString, err := bitstringGeneration(credIndices)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "duplicate status list index value found: 2")
		assert.Empty(tt, bitString)
	})
}
