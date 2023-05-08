package resolver

import (
	"reflect"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
)

// ResolutionResult encapsulates the tuple of a DID resolution https://www.w3.org/TR/did-core/#did-resolution
type ResolutionResult struct {
	Context            string `json:"@context,omitempty"`
	ResolutionMetadata `json:"didResolutionMetadata,omitempty"`
	did.Document       `json:"didDocument,omitempty"`
	DocumentMetadata   `json:"didDocumentMetadata,omitempty"`
}

func (r *ResolutionResult) IsEmpty() bool {
	if r == nil {
		return true
	}
	return reflect.DeepEqual(r, ResolutionResult{})
}

// DocumentMetadata https://www.w3.org/TR/did-core/#did-document-metadata
type DocumentMetadata struct {
	Created       string `json:"created,omitempty" validate:"datetime"`
	Updated       string `json:"updated,omitempty" validate:"datetime"`
	Deactivated   bool   `json:"deactivated,omitempty"`
	NextUpdate    string `json:"nextUpdate,omitempty"`
	VersionID     string `json:"versionId,omitempty"`
	NextVersionID string `json:"nextVersionId,omitempty"`
	EquivalentID  string `json:"equivalentId,omitempty"`
	CanonicalID   string `json:"canonicalId,omitempty"`
}

func (s *DocumentMetadata) IsValid() bool {
	return util.NewValidator().Struct(s) == nil
}

// ResolutionError https://www.w3.org/TR/did-core/#did-resolution-metadata
type ResolutionError struct {
	Code                       string `json:"code"`
	InvalidDID                 bool   `json:"invalidDid"`
	NotFound                   bool   `json:"notFound"`
	RepresentationNotSupported bool   `json:"representationNotSupported"`
}

// ResolutionMetadata https://www.w3.org/TR/did-core/#did-resolution-metadata
type ResolutionMetadata struct {
	ContentType string
	Error       *ResolutionError
}
