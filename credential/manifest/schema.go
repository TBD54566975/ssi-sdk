package manifest

import (
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/ssi-sdk/schema"
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
	s, err := schema.GetKnownSchema(credentialManifestSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential manifest schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Errorf("credential manifest not valid against schema")
		return err
	}
	return nil
}

// IsValidCredentialApplication validates a given credential application object against its known JSON schema
func IsValidCredentialApplication(application CredentialApplication) error {
	jsonBytes, err := json.Marshal(application)
	if err != nil {
		return errors.Wrap(err, "could not marshal application to JSON")
	}
	s, err := schema.GetKnownSchema(credentialApplicationSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential application schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("credential application not valid against schema")
		return err
	}
	return nil
}

// IsValidCredentialResponse validates a given credential response object against its known JSON schema
func IsValidCredentialResponse(response CredentialResponse) error {
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return errors.Wrap(err, "could not marshal response to JSON")
	}
	s, err := schema.GetKnownSchema(credentialResponseSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential response schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("credential response not valid against schema")
		return err
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
	s, err := schema.GetKnownSchema(outputDescriptorsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get output descriptors schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("output descriptors not valid against schema")
		return err
	}
	return nil
}
