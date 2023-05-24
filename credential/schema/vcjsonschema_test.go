package schema

import (
	"embed"
)

const (
	jsonSchema2023Credential1       string = "jsonschema2023-credential-1.json"
	jsonSchema2023Schema1           string = "jsonschema2023-schema-1.json"
	credentialSchema2023Credential1 string = "credentialschema2023-credential-1.json"
	credentialSchema2023Schema1     string = "credentialschema2023-schema-1.json"
)

var (
	//go:embed testdata
	testVectors embed.FS
)

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
