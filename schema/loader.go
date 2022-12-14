package schema

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/santhosh-tekuri/jsonschema/v5/httploader"
)

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

	PresentationClaimFormatDesignationFormatDefinition SchemaFile = "pe-submission-claim-format-designations.json"

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

// CachingLoader is a struct that holds local schemas
type CachingLoader struct {
	schemas sync.Map
}

// NewCachingLoader returns a new CachingLoader that enables the ability to cache http and https schemas
func NewCachingLoader(schemas map[string]string) (*CachingLoader, error) {
	// make sure only one process can write to the map at a time
	cl := CachingLoader{schemas: sync.Map{}}
	for schemaURI, schema := range schemas {
		if _, ok := cl.schemas.Load(schemaURI); ok {
			return nil, fmt.Errorf("schema %q already exists", schemaURI)
		}
		cl.schemas.Store(schemaURI, schema)
	}
	return &cl, nil
}

// EnableHTTPCache enables caching of http and https schemas
func (cl *CachingLoader) EnableHTTPCache() {
	jsonschema.Loaders["http"] = cl.cachingLoaderForProtocol("http")
	jsonschema.Loaders["https"] = cl.cachingLoaderForProtocol("https")
}

func (cl *CachingLoader) cachingLoaderForProtocol(protocol string) func(url string) (io.ReadCloser, error) {
	return func(url string) (io.ReadCloser, error) {
		// see if the schema is in the cache already
		schema, ok := cl.schemas.Load(strings.TrimPrefix(url, protocol+"://"))
		if ok {
			return io.NopCloser(strings.NewReader(schema.(string))), nil
		}

		// fallback lookup if it's stored with the fully qualified url
		schema, ok = cl.schemas.Load(url)
		if ok {
			return io.NopCloser(strings.NewReader(schema.(string))), nil
		}

		// load from the internet
		loaded, err := httploader.Load(url)
		if err != nil {
			return nil, errors.Wrapf(err, "loading schema from %s", protocol)
		}

		// read the contents and cache and prevent future lookups
		contents, err := io.ReadAll(loaded)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read schema from %s", protocol)
		}
		cl.schemas.Store(url, string(contents))

		return io.NopCloser(bytes.NewReader(contents)), nil
	}
}

// GetCachedSchemas returns an array of cached schema URIs
func (cl *CachingLoader) GetCachedSchemas() ([]string, error) {
	var schemas []string
	cl.schemas.Range(func(_, value interface{}) bool {
		schemas = append(schemas, value.(string))
		return true
	})
	return schemas, nil
}

// LoadSchema loads a schema from the embedded filesystem and returns its contents as  a json string
func LoadSchema(schemaFile SchemaFile) (string, error) {
	b, err := knownSchemas.ReadFile(schemaDirectory + schemaFile.String())
	return string(b), err
}

// GetAllLocalSchemas returns all locally cached schemas to be added to a CachingLoader
func GetAllLocalSchemas() (map[string]string, error) {
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

	localSchemas := make(map[string]string, len(localFiles))
	for k, v := range localFiles {
		gotSchema, err := LoadSchema(v)
		if err != nil {
			return nil, err
		}
		localSchemas[k] = gotSchema
	}

	return localSchemas, nil
}
