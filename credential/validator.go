package credential

import "github.com/gobuffalo/packr/v2"

const (
	PresentationDefinitionSchema = "pe-presentation-definition.json"
	SubmissionRequirementsSchema = "pe-submission-requirements.json"
	FormatDeclarationSchema      = "pe-format-declaration.json"
	CredentialApplicationSchema  = "cm-credential-application.json"
	CredentialFulfillmentSchema  = "cm-credential-fulfillment.json"
)

var (
	schemaBox = packr.New("Known Credential Manifest & Presentation Exchange Schemas", "./schema")
)

func getKnownSchema(fileName string) (string, error) {
	return schemaBox.FindString(fileName)
}
