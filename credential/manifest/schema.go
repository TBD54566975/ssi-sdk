package manifest

import (
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/gobuffalo/packr/v2"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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
	s, err := getKnownSchema(credentialApplicationSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential application schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("credential application not valid against schema")
		return err
	}
	return nil
}

// IsValidCredentialFulfillment validates a given credential fulfillment object against its known JSON schema
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
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("credential fulfillment not valid against schema")
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
	s, err := getKnownSchema(outputDescriptorsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get output descriptors schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("output descriptors not valid against schema")
		return err
	}
	return nil
}

func getKnownSchema(fileName string) (string, error) {
	return schemaBox.FindString(fileName)
}
