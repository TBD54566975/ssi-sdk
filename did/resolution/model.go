package resolution

import (
	"reflect"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
)

// Result encapsulates the tuple of a DID resolution https://www.w3.org/TR/did-core/#did-resolution
type Result struct {
	Context          string `json:"@context,omitempty"`
	*Metadata        `json:"didResolutionMetadata,omitempty"`
	did.Document     `json:"didDocument,omitempty"`
	DocumentMetadata `json:"didDocumentMetadata,omitempty"`
}

func (r *Result) IsEmpty() bool {
	if r == nil {
		return true
	}
	return reflect.DeepEqual(r, Result{})
}

type Method struct {
	Published          bool   `json:"published"`
	RecoveryCommitment string `json:"recoveryCommitment,omitempty"`
	UpdateCommitment   string `json:"updateCommitment,omitempty"`
}

// DocumentMetadata https://www.w3.org/TR/did-core/#did-document-metadata
type DocumentMetadata struct {
	Created       string   `json:"created,omitempty" validate:"omitempty,datetime=2006-01-02T15:04:05Z"`
	Updated       string   `json:"updated,omitempty" validate:"omitempty,datetime=2006-01-02T15:04:05Z"`
	Deactivated   bool     `json:"deactivated,omitempty"`
	NextUpdate    string   `json:"nextUpdate,omitempty"`
	VersionID     string   `json:"versionId,omitempty"`
	NextVersionID string   `json:"nextVersionId,omitempty"`
	EquivalentID  []string `json:"equivalentId,omitempty"`
	CanonicalID   string   `json:"canonicalId,omitempty"`
	Method        Method   `json:"method,omitempty"`
}

func (s *DocumentMetadata) IsValid() bool {
	return util.NewValidator().Struct(s) == nil
}

// Error https://www.w3.org/TR/did-core/#did-resolution-metadata
type Error struct {
	Code                       string `json:"code"`
	InvalidDID                 bool   `json:"invalidDid"`
	NotFound                   bool   `json:"notFound"`
	RepresentationNotSupported bool   `json:"representationNotSupported"`
}

// Metadata https://www.w3.org/TR/did-core/#did-resolution-metadata
type Metadata struct {
	ContentType string `json:"contentType,omitempty"`
	Error       *Error `json:"error,omitempty"`
}
