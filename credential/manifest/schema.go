package manifest

import (
	"github.com/TBD54566975/did-sdk/schema"
	"github.com/gobuffalo/packr/v2"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

const (
	credentialManifestSchema    string = "cm-credential-manifest.json"
	credentialApplicationSchema string = "cm-credential-application.json"
	credentialFulfillmentSchema string = "cm-credential-fulfillment.json"
	outputDescriptorsSchema     string = "cm-output-descriptors.json"
)

var (
	schemaBox = packr.New("Credential Manifest JSON Schemas", "../known_schemas")
)

func IsValidCredentialManifest(manifest CredentialManifest) error {
	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		return errors.Wrap(err, "could not marshal manifest to JSON")
	}
	s, err := getKnownSchema(credentialManifestSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential manifest schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func IsValidCredentialApplication(application CredentialApplication) error {
	jsonBytes, err := json.Marshal(application)
	if err != nil {
		return errors.Wrap(err, "could not marshal application to JSON")
	}
	s, err := getKnownSchema(credentialApplicationSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential application schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func IsValidCredentialFulfillment(fulfillment CredentialFulfillment) error {
	fulfillmentWrapper := struct {
		CredentialFulfillment `json:"credential_fulfillment"`
	}{
		CredentialFulfillment: fulfillment,
	}
	jsonBytes, err := json.Marshal(fulfillmentWrapper)
	if err != nil {
		return errors.Wrap(err, "could not marshal fulfillment to JSON")
	}
	s, err := getKnownSchema(credentialFulfillmentSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential fulfillment schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func AreValidOutputDescriptors(descriptors []OutputDescriptor) error {
	descriptorsWrapper := struct {
		OutputDescriptors []OutputDescriptor `json:"output_descriptors"`
	}{
		OutputDescriptors: descriptors,
	}
	jsonBytes, err := json.Marshal(descriptorsWrapper)
	if err != nil {
		return errors.Wrap(err, "could not marshal output descriptors to JSON")
	}
	s, err := getKnownSchema(outputDescriptorsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get output descriptors schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func getKnownSchema(fileName string) (string, error) {
	return schemaBox.FindString(fileName)
}
