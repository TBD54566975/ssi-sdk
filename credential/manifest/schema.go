package manifest

import (
	"embed"
	"strings"

	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

var (
	//go:embed known_schemas
	knownSchemas embed.FS
)

type CredentialManifestSchema string

func (cm CredentialManifestSchema) String() string {
	return string(cm)
}

const (
	CredentialManifestManifestSchema CredentialManifestSchema = "cm-credential-manifest.json"
	CredentialApplicationSchema      CredentialManifestSchema = "cm-credential-application.json"
	CredentialResponseSchema         CredentialManifestSchema = "cm-credential-response.json"
	OutputDescriptorsSchema          CredentialManifestSchema = "cm-output-descriptors.json"
)

func (CredentialManifestSchema) LocalLoad() (map[string]string, error) {
	schemaDirectory := "known_schemas"
	local := map[string]string{
		"https://identity.foundation/credential-manifest/schemas/credential-manifest.json":    strings.Join([]string{schemaDirectory, CredentialManifestManifestSchema.String()}, "/"),
		"https://identity.foundation/credential-manifest/schemas/credential-application.json": strings.Join([]string{schemaDirectory, CredentialApplicationSchema.String()}, "/"),
		"https://identity.foundation/credential-manifest/schemas/credential-response.json":    strings.Join([]string{schemaDirectory, CredentialResponseSchema.String()}, "/"),
		"https://identity.foundation/credential-manifest/schemas/output-descriptors.json":     strings.Join([]string{schemaDirectory, OutputDescriptorsSchema.String()}, "/"),
	}
	for k, v := range local {
		schemaBytes, err := knownSchemas.ReadFile(v)
		if err != nil {
			return nil, err
		}
		local[k] = string(schemaBytes)
	}
	return local, nil
}

// IsValidCredentialManifest validates a given credential manifest object against its known JSON schema
func IsValidCredentialManifest(manifest CredentialManifest) error {
	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		return errors.Wrap(err, "could not marshal manifest to JSON")
	}
	s, err := GetCredentialManifestSchema(CredentialManifestManifestSchema)
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
	s, err := GetCredentialManifestSchema(CredentialApplicationSchema)
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
	s, err := GetCredentialManifestSchema(CredentialResponseSchema)
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
	s, err := GetCredentialManifestSchema(OutputDescriptorsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get output descriptors schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "output descriptors not valid against schema")
	}
	return nil
}

func GetCredentialManifestSchema(schemaFile CredentialManifestSchema) (string, error) {
	b, err := knownSchemas.ReadFile("known_schemas/" + schemaFile.String())
	return string(b), err
}
