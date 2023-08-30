package manifest

import (
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// IsValidCredentialManifest validates a given credential manifest object against its known JSON schema
func IsValidCredentialManifest(manifest CredentialManifest) error {
	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		return errors.Wrap(err, "marshaling manifest to JSON")
	}
	s, err := schema.LoadSchema(schema.CredentialManifestSchema)
	if err != nil {
		return errors.Wrap(err, "getting credential manifest schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "credential manifest not valid against schema")
	}
	return nil
}

// IsValidCredentialApplication validates a given credential application object against its known JSON schema
func IsValidCredentialApplication(application CredentialApplication) error {
	jsonBytes, err := json.Marshal(application)
	if err != nil {
		return errors.Wrap(err, "marshaling application to JSON")
	}
	s, err := schema.LoadSchema(schema.CredentialApplicationSchema)
	if err != nil {
		return errors.Wrap(err, "getting credential application schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "credential application not valid against schema")
	}
	return nil
}

// IsValidCredentialResponse validates a given credential response object against its known JSON schema
func IsValidCredentialResponse(response CredentialResponse) error {
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return errors.Wrap(err, "marshaling response to JSON")
	}
	s, err := schema.LoadSchema(schema.CredentialResponseSchema)
	if err != nil {
		return errors.Wrap(err, "getting credential response schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
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
		return errors.Wrap(err, "marshaling output descriptors to JSON")
	}
	s, err := schema.LoadSchema(schema.OutputDescriptorsSchema)
	if err != nil {
		return errors.Wrap(err, "getting output descriptors schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "output descriptors not valid against schema")
	}
	return nil
}
