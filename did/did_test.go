package did

import (
	"encoding/json"
	"testing"

	"github.com/gobuffalo/packr/v2"
	"github.com/stretchr/testify/assert"
)

const (
	TestVector1 string = "example-30.json"
	TestVector2 string = "example-31.json"
	TestVector3 string = "example-32.json"
)

var (
	box         = packr.New("DID Test Vectors", "./test_vectors")
	testVectors = []string{TestVector1, TestVector2, TestVector3}
)

func TestDIDVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for _, tv := range testVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		var did DIDDocument
		err = json.Unmarshal([]byte(gotTestVector), &did)
		assert.NoError(t, err)

		didBytes, err := json.Marshal(did)
		assert.NoError(t, err)
		assert.JSONEqf(t, gotTestVector, string(didBytes), "error message %s")
	}
}

func getTestVector(fileName string) (string, error) {
	return box.FindString(fileName)
}
