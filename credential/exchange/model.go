package exchange

import "github.com/TBD54566975/did-sdk/util"

type (
	Selection            string
	DisclosurePreference string
	CredentialFormat     string
	JWTFormat            CredentialFormat
	LinkedDataFormat     CredentialFormat
)

const (
	JWT   JWTFormat = "jwt"
	JWTVC JWTFormat = "jwt_vc"
	JWTVP JWTFormat = "jwt_vp"

	LDP   LinkedDataFormat = "ldp"
	LDPVC LinkedDataFormat = "ldp_vc"
	LDPVP LinkedDataFormat = "ldp_vp"

	All  Selection = "all"
	Pick Selection = "pick"

	Required  DisclosurePreference = "required"
	Preferred DisclosurePreference = "preferred"
)

// PresentationDefinition https://identity.foundation/presentation-exchange/#presentation-definition
type PresentationDefinition struct {
	ID                     string                  `json:"id" validate:"required"`
	InputDescriptors       []InputDescriptor       `json:"input_descriptors" validate:"required,dive"`
	Name                   string                  `json:"name,omitempty"`
	Purpose                string                  `json:"purpose,omitempty"`
	Format                 *ClaimFormat            `json:"format,omitempty" validate:"dive"`
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty" validate:"dive"`
}

func (pd *PresentationDefinition) IsValid() error {
	return util.NewValidator().Struct(pd)
}

// ClaimFormat https://identity.foundation/presentation-exchange/#claim-format-designations
// At most one field can have non-nil
type ClaimFormat struct {
	JWT   *JWTType `json:"jwt,omitempty" validate:"dive"`
	JWTVC *JWTType `json:"jwt_vc,omitempty" validate:"dive"`
	JWTVP *JWTType `json:"jwt_vp,omitempty" validate:"dive"`

	LDP   *LDPType `json:"ldp,omitempty" validate:"dive"`
	LDPVC *LDPType `json:"ldp_vc,omitempty" validate:"dive"`
	LDPVP *LDPType `json:"ldp_vp,omitempty" validate:"dive"`
}

type JWTType struct {
	Alg []string `json:"alg" validate:"required"`
}

type LDPType struct {
	ProofType []string `json:"proof_type" validate:"required"`
}

type InputDescriptor struct {
	// Must be unique within the Presentation Definition
	ID   string `json:"id,omitempty" validate:"required"`
	Name string `json:"name,omitempty"`
	// Purpose for which claim's data is being requested
	Purpose     string       `json:"purpose,omitempty"`
	Format      *ClaimFormat `json:"format,omitempty" validate:"dive"`
	Constraints *Constraints `json:"constraints,omitempty"`
}

type Constraints struct {
	Fields          []Field               `json:"fields,omitempty"`
	LimitDisclosure *DisclosurePreference `json:"limit_disclosure,omitempty"`
	SubjectIsIssuer *DisclosurePreference `json:"subject_is_issuer,omitempty"`
	SubjectIsHolder *DisclosurePreference `json:"subject_is_holder,omitempty"`
}

type Field struct {
	Path      []string              `json:"path,omitempty" validate:"required"`
	ID        string                `json:"id,omitempty"`
	Purpose   string                `json:"purpose,omitempty"`
	Filter    *Filter               `json:"filter,omitempty"`
	Predicate *DisclosurePreference `json:"predicate,omitempty"`
}

type Filter struct {
	Type             string        `json:"type" validate:"required"`
	Format           string        `json:"format,omitempty"`
	Pattern          string        `json:"pattern,omitempty"`
	Minimum          interface{}   `json:"minimum,omitempty"`
	Maximum          interface{}   `json:"maximum,omitempty"`
	MinLength        int           `json:"minLength,omitempty"`
	MaxLength        int           `json:"maxLength,omitempty"`
	ExclusiveMinimum interface{}   `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum interface{}   `json:"exclusiveMaximum,omitempty"`
	Const            interface{}   `json:"const,omitempty"`
	Enum             []interface{} `json:"enum,omitempty"`
	Not              interface{}   `json:"not,omitempty"`
}

type SubmissionRequirement struct {
	Name    string    `json:"name,omitempty"`
	Purpose string    `json:"purpose,omitempty"`
	Rule    Selection `json:"rule" validate:"required"`
	Count   int       `json:"count,omitempty" validate:"min=1"`
	Minimum int       `json:"min,omitempty"`
	Maximum int       `json:"max,omitempty"`

	// Either an array of SubmissionRequirement or a string value
	FromOption `validate:"required"`
}

type FromOption struct {
	From       string                  `json:"from,omitempty"`
	FromNested []SubmissionRequirement `json:"from_nested,omitempty"`
}
