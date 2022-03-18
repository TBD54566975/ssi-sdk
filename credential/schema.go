package credential

import (
	"github.com/TBD54566975/did-sdk/credential/manifest"
	"github.com/TBD54566975/did-sdk/schema"
	"github.com/gobuffalo/packr/v2"
)

const (
	CredentialManifestSchema                         string = "cm-credential-manifest.json"
	CredentialManifesApplicationtSchema              string = "cm-credential-application.json"
	CredentialManifestFulfillmentSchema              string = "cm-credential-fulfillment.json"
	CredentialManifestOutputDescriptorsSchema        string = "cm-output-descriptors.json"
	PresentationExchangeDefinitionSchema             string = "pe-presentation-definition.json"
	PresentationExchangeFormatDeclarationSchema      string = "pe-format-declaration.json"
	PresentationExchangeSubmissionRequirementsSchema string = "pe-submission-requirements.json"
)

var (
	schemaBox = packr.New("Presentation Exchange & Credential Manifest JSON Schemas", "schemas")
)

func IsValidCredentialManifest(manifest manifest.CredentialManifest) error {
	schema.IsJSONValidAgainstSchema()
}

func getKnownSchema(fileName string) (string, error) {
	return schemaBox.FindString(fileName)
}
