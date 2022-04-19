package schema

import (
	vc "github.com/TBD54566975/ssi-sdk/credential"
	"testing"

	"github.com/goccy/go-json"

	"github.com/stretchr/testify/assert"

	"github.com/gobuffalo/packr/v2"
)

const (
	vcJSONTestVector1           string = "vc-json-schema-example-1.json"
	vcJSONCredentialTestVector1 string = "vc-with-schema-example-11.json"
)

var (
	testSchemaBox     = packr.New("VC JSON Schema Test Vectors", "../test_vectors")
	vcJSONTestVectors = []string{vcJSONTestVector1}
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
	credential, err := getTestVector(vcJSONCredentialTestVector1)
	assert.NoError(t, err)
	var cred vc.VerifiableCredential
	err = json.Unmarshal([]byte(credential), &cred)
	assert.NoError(t, err)

	// Load vcJSONSchema
	vcJSONSchemaString, err := getTestVector(vcJSONTestVector1)
	assert.NoError(t, err)

	vcJSONSchema, err := StringToVCJSONCredentialSchema(vcJSONSchemaString)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcJSONSchema)

	// Validate credential against vcJSONSchema
	err = IsCredentialValidForVCJSONSchema(cred, *vcJSONSchema)
	assert.NoError(t, err)
}

func getTestVector(fileName string) (string, error) {
	return testSchemaBox.FindString(fileName)
}
