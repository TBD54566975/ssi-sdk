package did

import (
	"embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
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

		var did DIDDocument
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
	emptyDoc := DIDDocument{}
	assert.True(t, emptyDoc.IsEmpty())

	var nilDID *DIDDocument
	nilDID = nil
	assert.True(t, nilDID.IsEmpty())

	// not empty
	did := DIDDocument{
		ID: "did:test:123",
	}
	assert.False(t, did.IsEmpty())
}

func TestDIDDocumentMetadata(t *testing.T) {
	// good
	metadata := DIDDocumentMetadata{}
	assert.True(t, metadata.IsValid())

	// bad
	badMetadata := DIDDocumentMetadata{
		Created: "bad",
		Updated: time.Now().UTC().Format(time.RFC3339),
	}
	assert.False(t, badMetadata.IsValid())
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectorFS.ReadFile("testdata/" + fileName)
	return string(b), err
}

func TestKeyTypeToLDKeyType(t *testing.T) {
	kt, err := KeyTypeToLDKeyType(crypto.Ed25519)
	assert.NoError(t, err)
	assert.Equal(t, kt, cryptosuite.Ed25519VerificationKey2018)

	kt, err = KeyTypeToLDKeyType(crypto.X25519)
	assert.NoError(t, err)
	assert.Equal(t, kt, cryptosuite.X25519KeyAgreementKey2019)

	kt, err = KeyTypeToLDKeyType(crypto.SECP256k1)
	assert.NoError(t, err)
	assert.Equal(t, kt, cryptosuite.EcdsaSecp256k1VerificationKey2019)

	kt, err = KeyTypeToLDKeyType(crypto.Ed25519)
	assert.NoError(t, err)
	assert.Equal(t, kt, cryptosuite.Ed25519VerificationKey2018)

	kt, err = KeyTypeToLDKeyType(crypto.P256)
	assert.NoError(t, err)
	assert.Equal(t, kt, cryptosuite.JSONWebKey2020Name)

	_, err = KeyTypeToLDKeyType(crypto.KeyType("bad"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported keyType")
}
