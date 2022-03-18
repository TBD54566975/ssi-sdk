package schema

import (
	vc "github.com/TBD54566975/did-sdk/credential"
	"testing"

	"github.com/goccy/go-json"

	"github.com/stretchr/testify/assert"

	"github.com/gobuffalo/packr/v2"
)

const (
	VCJSONTestVector1           string = "vc-json-schema-example-1.json"
	VCJSONCredentialTestVector1 string = "vc-with-schema-example-11.json"
)

var (
	box               = packr.New("VC JSON Schema Test Vectors", "test_vectors")
	vcJSONTestVectors = []string{VCJSONTestVector1}
)

// Before running, you'll need to execute `mage packr`
func TestIsValidCredentialSchema(t *testing.T) {
	for _, tv := range vcJSONTestVectors {
		schema, err := getTestVector(tv)
		assert.NoError(t, err)
		assert.NoError(t, IsValidCredentialSchema(schema))
	}
}

func TestIsCredentialValidForSchema(t *testing.T) {
	// Load VC
	credential, err := getTestVector(VCJSONCredentialTestVector1)
	var cred vc.VerifiableCredential
	err = json.Unmarshal([]byte(credential), &cred)
	assert.NoError(t, err)

	// Load vcJSONSchema
	vcJSONSchemaString, err := getTestVector(VCJSONTestVector1)
	assert.NoError(t, err)

	vcJSONSchema, err := StringToVCJSONCredentialSchema(vcJSONSchemaString)
	assert.NoError(t, err)

	// Validate credential against vcJSONSchema
	err = IsCredentialValidForVCJSONSchema(cred, *vcJSONSchema)
	assert.NoError(t, err)
}

func getTestVector(fileName string) (string, error) {
	return box.FindString(fileName)
}
