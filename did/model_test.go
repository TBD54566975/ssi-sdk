package did

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"

	"github.com/stretchr/testify/assert"
)

// These test vectors are taken from the did-core spec example
// e.g. https://www.w3.org/TR/did-core/#example-30-did-document-with-1-verification-method-type
const (
	TestVector1 string = "did-example-30.json"
	TestVector2 string = "did-example-31.json"
	TestVector3 string = "did-example-32.json"
)

var (
	//go:embed testdata
	testVectorFS embed.FS
	testVectors  = []string{TestVector1, TestVector2, TestVector3}
)

func TestDIDVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for _, tv := range testVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		var did Document
		err = json.Unmarshal([]byte(gotTestVector), &did)
		assert.NoError(t, err)

		assert.NoError(t, did.IsValid())
		assert.False(t, did.IsEmpty())

		didBytes, err := json.Marshal(did)
		assert.NoError(t, err)
		assert.JSONEqf(t, gotTestVector, string(didBytes), "Error message %s")
	}
}

func TestDIDDocument(t *testing.T) {
	// empty
	emptyDoc := Document{}
	assert.True(t, emptyDoc.IsEmpty())

	var nilDID *Document
	nilDID = nil
	assert.True(t, nilDID.IsEmpty())

	// not empty
	did := Document{
		ID: "did:test:123",
	}
	assert.False(t, did.IsEmpty())
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectorFS.ReadFile("testdata/" + fileName)
	return string(b), err
}
