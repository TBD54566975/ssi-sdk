//go:build jwx_es256k

package did

import (
	"testing"

	"github.com/goccy/go-json"

	"github.com/gobuffalo/packr/v2"
	"github.com/stretchr/testify/assert"
)

// These test vectors are taken from the did-core spec examples
// e.g. https://www.w3.org/TR/did-core/#example-30-did-document-with-1-verification-method-type
const (
	TestVector1 string = "did-example-30.json"
	TestVector2 string = "did-example-31.json"
	TestVector3 string = "did-example-32.json"
)

var (
	box         = packr.New("DID Test Vectors", "./test_vectors")
	testVectors = []string{TestVector1, TestVector2, TestVector3}
)

// Before running, you'll need to execute `mage packr`
func TestDIDVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for _, tv := range testVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		var did DIDDocument
		err = json.Unmarshal([]byte(gotTestVector), &did)
		assert.NoError(t, err)

		assert.NoError(t, did.IsValid())
		assert.False(t, did.IsEmpty())

		didBytes, err := json.Marshal(did)
		assert.NoError(t, err)
		assert.JSONEqf(t, gotTestVector, string(didBytes), "error message %s")
	}
}

func getTestVector(fileName string) (string, error) {
	return box.FindString(fileName)
}
