package resolution

import (
	"reflect"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
)

// Result encapsulates the tuple of a DID resolution https://www.w3.org/TR/did-core/#did-resolution
type Result struct {
	Context           string `json:"@context,omitempty"`
	Metadata          `json:"didResolutionMetadata"`
	did.Document      `json:"didDocument,omitempty"`
	*DocumentMetadata `json:"didDocumentMetadata,omitempty"`
}

func (r *Result) IsEmpty() bool {
	if r == nil {
		return true
	}
	return reflect.DeepEqual(r, Result{})
}

type Method struct {
	// The `method` property in https://identity.foundation/sidetree/spec/#did-resolver-output
	Published bool `json:"published"`

	// The `recoveryCommitment` property in https://identity.foundation/sidetree/spec/#did-resolver-output
	RecoveryCommitment string `json:"recoveryCommitment,omitempty"`

	// The `updateCommitment` property in https://identity.foundation/sidetree/spec/#did-resolver-output
	UpdateCommitment string `json:"updateCommitment,omitempty"`
}

// DocumentMetadata https://www.w3.org/TR/did-core/#did-document-metadata
type DocumentMetadata struct {
	// See `created` in https://www.w3.org/TR/did-core/#did-document-metadata
	Created string `json:"created,omitempty" validate:"omitempty,datetime=2006-01-02T15:04:05Z"`

	// See `updated` in https://www.w3.org/TR/did-core/#did-document-metadata
	Updated string `json:"updated,omitempty" validate:"omitempty,datetime=2006-01-02T15:04:05Z"`

	// See `deactivated` in https://www.w3.org/TR/did-core/#did-document-metadata
	Deactivated bool `json:"deactivated,omitempty"`

	// See `nextUpdate` in https://www.w3.org/TR/did-core/#did-document-metadata
	NextUpdate string `json:"nextUpdate,omitempty"`

	// See `versionId` in https://www.w3.org/TR/did-core/#did-document-metadata
	VersionID string `json:"versionId,omitempty"`

	// See `nextVersionId` in https://www.w3.org/TR/did-core/#did-document-metadata
	NextVersionID string `json:"nextVersionId,omitempty"`

	// See `equivalentId` in https://www.w3.org/TR/did-core/#did-document-metadata
	EquivalentID []string `json:"equivalentId,omitempty"`

	// See `canonicalId` in https://www.w3.org/TR/did-core/#did-document-metadata
	CanonicalID string `json:"canonicalId,omitempty"`

	// Optional information that is specific to the DID Method of the DID Document resolved. Populated only
	// for sidetree based did methods (e.g. ION), as described in https://identity.foundation/sidetree/spec/#did-resolver-output
	Method Method `json:"method,omitempty"`
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
