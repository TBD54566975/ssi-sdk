package schema

import (
	"embed"
	"fmt"
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func init() {
	// load all local schemas
	if err := LoadAllLocal(); err != nil {
		panic(err)
	}
}

var (
	//go:embed known_schemas
	knownSchemas embed.FS
)

type (
	SchemaFile string
)

const (
	schemaDirectory = "known_schemas/"

	// Presentation Exchange Schemas
	PresentationDefinitionSchema              SchemaFile = "pe-presentation-definition.json"
	PresentationDefinitionEnvelopeSchema      SchemaFile = "pe-presentation-definition-envelope.json"
	PresentationSubmissionSchema              SchemaFile = "pe-presentation-submission.json"
	PresentationClaimFormatDesignationsSchema SchemaFile = "pe-definition-claim-format-designations.json"
	SubmissionClaimFormatDesignationsSchema   SchemaFile = "pe-submission-claim-format-designations.json"
	SubmissionRequirementSchema               SchemaFile = "pe-submission-requirement.json"
	SubmissionRequirementsSchema              SchemaFile = "pe-submission-requirements.json"

	// Credential Manifest Schemas
	CredentialManifestSchema    SchemaFile = "cm-credential-manifest.json"
	CredentialApplicationSchema SchemaFile = "cm-credential-application.json"
	CredentialResponseSchema    SchemaFile = "cm-credential-response.json"
	OutputDescriptorsSchema     SchemaFile = "cm-output-descriptors.json"

	// Wallet Rendering Schemas
	DisplayMappingObjectSchema        SchemaFile = "wr-display-mapping-object.json"
	EntityStylesSchema                SchemaFile = "wr-entity-styles.json"
	LabeledDisplayMappingObjectSchema SchemaFile = "wr-labeled-display-mapping-object.json"

	// VC JSON Schema Schemas
	VerifiableCredentialJSONSchemaSchema SchemaFile = "vc-json-schema.json"
)

func (s SchemaFile) String() string {
	return string(s)
}

// LocalLoader is a struct that holds local schemas
type LocalLoader struct {
	localSchemas map[string]string
}

// NewLocalLoader returns a new LocalLoader without any schemas to be loaded locally
// Calling this method disables the ability to load schemas remotely over http and https
func NewLocalLoader() LocalLoader {
	localSchemas := make(map[string]string)
	jsonschema.Loaders["https"] = func(url string) (io.ReadCloser, error) {
		schema, ok := localSchemas[strings.TrimPrefix(url, "https://")]
		if !ok {
			return nil, fmt.Errorf("%q not found", url)
		}
		return io.NopCloser(strings.NewReader(schema)), nil
	}
	jsonschema.Loaders["http"] = func(url string) (io.ReadCloser, error) {
		schema, ok := localSchemas[strings.TrimPrefix(url, "http://")]
		if !ok {
			return nil, fmt.Errorf("%q not found", url)
		}
		return io.NopCloser(strings.NewReader(schema)), nil
	}
	return LocalLoader{localSchemas: localSchemas}
}

// AddLocalLoad adds a set of schemas from an implementer of `LoadLocal` to the local loader
func (l *LocalLoader) AddLocalLoad(localSchemas map[string]string) error {
	if l.localSchemas == nil {
		return errors.New("local loading is not instantiated")
	}
	for schemaName, schemaValue := range localSchemas {
		l.localSchemas[schemaName] = schemaValue
	}
	return nil
}

// LoadAllLocal loads all local schemas from a known of LoadLocal implementers
func LoadAllLocal() error {
	localFiles := map[string]SchemaFile{
		"identity.foundation/presentation-exchange/schemas/presentation-definition.json":                           PresentationDefinitionSchema,
		"identity.foundation/presentation-exchange/schemas/presentation-definition-envelope.json":                  PresentationDefinitionEnvelopeSchema,
		"identity.foundation/presentation-exchange/schemas/presentation-submission.json":                           PresentationSubmissionSchema,
		"identity.foundation/claim-format-registry/schemas/presentation-definition-claim-format-designations.json": PresentationClaimFormatDesignationsSchema,
		"identity.foundation/claim-format-registry/schemas/presentation-submission-claim-format-designations.json": SubmissionClaimFormatDesignationsSchema,
		"identity.foundation/presentation-exchange/schemas/submission-requirement.json":                            SubmissionRequirementSchema,
		"identity.foundation/presentation-exchange/schemas/submission-requirements.json":                           SubmissionRequirementsSchema,
		"identity.foundation/credential-manifest/schemas/credential-manifest.json":                                 CredentialManifestSchema,
		"identity.foundation/credential-manifest/schemas/credential-application.json":                              CredentialApplicationSchema,
		"identity.foundation/credential-manifest/schemas/credential-response.json":                                 CredentialResponseSchema,
		"identity.foundation/credential-manifest/schemas/output-descriptors.json":                                  OutputDescriptorsSchema,
		"identity.foundation/wallet-rendering/schemas/display-mapping-object.json":                                 DisplayMappingObjectSchema,
		"identity.foundation/wallet-rendering/schemas/entity-styles.json":                                          EntityStylesSchema,
		"identity.foundation/wallet-rendering/schemas/labeled-display-mapping-object.json":                         LabeledDisplayMappingObjectSchema,
		"w3c-ccg.github.io/vc-json-schemas/credential-schema-2.0":                                                  VerifiableCredentialJSONSchemaSchema,
	}

	localSchemas := make(map[string]string)
	for k, v := range localFiles {
		gotSchema, err := LoadSchema(v)
		if err != nil {
			return errors.Wrapf(err, "failed to load schema %s", k)
		}
		localSchemas[k] = gotSchema
	}

	localLoader := NewLocalLoader()
	if err := localLoader.AddLocalLoad(localSchemas); err != nil {
		return errors.Wrap(err, "could not load local schemas")
	}
	return nil
}

// DisableLocalLoad disables the ability to load schemas locally, clearing current locally loaded schemas
func DisableLocalLoad() {
	jsonschema.Loaders["https"] = nil
	jsonschema.Loaders["http"] = nil
}

func LoadSchema(schemaFile SchemaFile) (string, error) {
	b, err := knownSchemas.ReadFile(schemaDirectory + schemaFile.String())
	return string(b), err
}
