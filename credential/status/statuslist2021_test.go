package status

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestBitstringGeneration(t *testing.T) {
    credIndices := []string{"123", "1", "440185", "52058", "9999"}
    bitString, err := bitstringGeneration(credIndices)
    assert.NoError(t, err)
    assert.NotEmpty(t, bitString)

    expanded, err := bitstringExpansion(bitString)
    assert.NoError(t, err)
    assert.NotEmpty(t, expanded)

    println(bitString)
    println(expanded)

}
