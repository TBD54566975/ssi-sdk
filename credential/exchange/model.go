package exchange

import "github.com/TBD54566975/did-sdk/util"

type (
	Selection        string
	Preference       string
	CredentialFormat string
	JWTFormat        CredentialFormat
	LinkedDataFormat CredentialFormat
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

	// Used for limiting disclosure, predicates, and relational constraints

	Required   Preference = "required"
	Preferred  Preference = "preferred"
	Allowed    Preference = "allowed"
	Disallowed Preference = "disallowed"
)

// PresentationDefinition https://identity.foundation/presentation-exchange/#presentation-definition
type PresentationDefinition struct {
	ID                     string                  `json:"id" validate:"required"`
	InputDescriptors       []InputDescriptor       `json:"input_descriptors" validate:"required,dive"`
	Name                   string                  `json:"name,omitempty"`
	Purpose                string                  `json:"purpose,omitempty"`
	Format                 *ClaimFormat            `json:"format,omitempty" validate:"dive"`
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty" validate:"dive"`

	// https://identity.foundation/presentation-exchange/#json-ld-framing-feature
	Frame interface{} `json:"frame,omitempty"`
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
	// Must match a grouping strings listed in the `from` values of a submission requirement rule
	Group []string `json:"group,omitempty"`
}

type Constraints struct {
	Fields          []Field     `json:"fields,omitempty"`
	LimitDisclosure *Preference `json:"limit_disclosure,omitempty"`

	// https://identity.foundation/presentation-exchange/#relational-constraint-feature
	SubjectIsIssuer *Preference           `json:"subject_is_issuer,omitempty"`
	IsHolder        *RelationalConstraint `json:"is_holder,omitempty" validate:"dive"`
	SameSubject     *RelationalConstraint `json:"same_subject,omitempty"`

	// https://identity.foundation/presentation-exchange/#credential-status-constraint-feature
	Statuses *CredentialStatus `json:"statuses,omitempty"`
}

type Field struct {
	Path    []string `json:"path,omitempty" validate:"required"`
	ID      string   `json:"id,omitempty"`
	Purpose string   `json:"purpose,omitempty"`
	// If a predicate property is present, filter must be too
	// https://identity.foundation/presentation-exchange/#predicate-feature
	Predicate *Preference `json:"predicate,omitempty"`
	Filter    *Filter     `json:"filter,omitempty"`
}

type RelationalConstraint struct {
	FieldID   string     `json:"field_id" validate:"required"`
	Directive Preference `json:"directive" validate:"required"`
}

type Filter struct {
	Type             string      `json:"type" validate:"required"`
	Format           string      `json:"format,omitempty"`
	Pattern          string      `json:"pattern,omitempty"`
	Minimum          interface{} `json:"minimum,omitempty"`
	Maximum          interface{} `json:"maximum,omitempty"`
	MinLength        int         `json:"minLength,omitempty"`
	MaxLength        int         `json:"maxLength,omitempty"`
	ExclusiveMinimum interface{} `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum interface{} `json:"exclusiveMaximum,omitempty"`
	// TODO(gabe) these may not be valid https://github.com/decentralized-identity/presentation-exchange/issues/312
	FormatMinimum interface{}   `json:"formatMinimum,omitempty"`
	FormatMaximum interface{}   `json:"formatMaximum,omitempty"`
	Const         interface{}   `json:"const,omitempty"`
	Enum          []interface{} `json:"enum,omitempty"`
	Not           interface{}   `json:"not,omitempty"`
}

// CredentialStatus https://identity.foundation/presentation-exchange/#credential-status-constraint-feature
type CredentialStatus struct {
	Active    *ActiveStatus    `json:"active,omitempty"`
	Suspended *SuspendedStatus `json:"suspended,omitempty"`
	Revoked   *RevokedStatus   `json:"revoked,omitempty"`
}

type ActiveStatus struct {
	Directive Preference `json:"directive,omitempty"`
}

type SuspendedStatus struct {
	Directive Preference `json:"directive,omitempty"`
}

type RevokedStatus struct {
	Directive Preference `json:"directive,omitempty"`
}

// SubmissionRequirement https://identity.foundation/presentation-exchange/#presentation-definition-extensions
type SubmissionRequirement struct {
	Rule Selection `json:"rule" validate:"required"`
	// Either an array of SubmissionRequirement OR a string value
	FromOption `validate:"required"`

	Name    string `json:"name,omitempty"`
	Purpose string `json:"purpose,omitempty"`
	Count   int    `json:"count,omitempty" validate:"min=1"`
	Minimum int    `json:"min,omitempty"`
	Maximum int    `json:"max,omitempty"`
}

type FromOption struct {
	From       string                  `json:"from,omitempty"`
	FromNested []SubmissionRequirement `json:"from_nested,omitempty"`
}

// PresentationSubmission https://identity.foundation/presentation-exchange/#presentation-submission
type PresentationSubmission struct {
	ID            string                 `json:"id" validate:"required"`
	DefinitionID  string                 `json:"definition_id" validate:"required"`
	DescriptorMap []SubmissionDescriptor `json:"descriptor_map" validate:"required"`
}

// SubmissionDescriptor is a mapping to Input Descriptor objects
type SubmissionDescriptor struct {
	// Must match the `id` property of the corresponding input descriptor
	ID         string            `json:"id" validate:"required"`
	Format     string            `json:"format" validate:"required"`
	Path       string            `json:"path" validate:"required"`
	PathNested *NestedDescriptor `json:"path_nested,omitempty"`
}

type NestedDescriptor struct {
	*SubmissionDescriptor
}
