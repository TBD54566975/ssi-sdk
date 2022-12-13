package manifest

import (
	"embed"

	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

var (
	//go:embed known_schemas
	knownSchemas embed.FS
)

const (
	credentialManifestSchema    string = "cm-credential-manifest.json"
	credentialApplicationSchema string = "cm-credential-application.json"
	credentialResponseSchema    string = "cm-credential-response.json"
	outputDescriptorsSchema     string = "cm-output-descriptors.json"
)

// IsValidCredentialManifest validates a given credential manifest object against its known JSON schema
func IsValidCredentialManifest(manifest CredentialManifest) error {
	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		return errors.Wrap(err, "could not marshal manifest to JSON")
	}
	s, err := getKnownSchema(credentialManifestSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential manifest schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "credential manifest not valid against schema")
	}
	return nil
}

// IsValidCredentialApplication validates a given credential application object against its known JSON schema
func IsValidCredentialApplication(application CredentialApplication) error {
	jsonBytes, err := json.Marshal(application)
	if err != nil {
		return errors.Wrap(err, "could not marshal application to JSON")
	}
	s, err := getKnownSchema(credentialApplicationSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential application schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "credential application not valid against schema")
	}
	return nil
}

// IsValidCredentialResponse validates a given credential response object against its known JSON schema
func IsValidCredentialResponse(response CredentialResponse) error {
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return errors.Wrap(err, "could not marshal response to JSON")
	}
	s, err := getKnownSchema(credentialResponseSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential response schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "credential response not valid against schema")
	}
	return nil
}

// AreValidOutputDescriptors validates a set of output descriptor objects against its known JSON schema
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
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "output descriptors not valid against schema")
	}
	return nil
}

func getKnownSchema(fileName string) (string, error) {
	b, err := knownSchemas.ReadFile("known_schemas/" + fileName)
	return string(b), err
}
