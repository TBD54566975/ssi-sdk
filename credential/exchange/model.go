//go:build jwx_es256k

package exchange

import (
	"github.com/TBD54566975/did-sdk/crypto"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/TBD54566975/did-sdk/util"
	"github.com/pkg/errors"
	"reflect"
)

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
	ID                     string                  `json:"id,omitempty" validate:"required"`
	InputDescriptors       []InputDescriptor       `json:"input_descriptors,omitempty" validate:"required,dive"`
	Name                   string                  `json:"name,omitempty"`
	Purpose                string                  `json:"purpose,omitempty"`
	Format                 *ClaimFormat            `json:"format,omitempty" validate:"omitempty,dive"`
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty" validate:"omitempty,dive"`

	// https://identity.foundation/presentation-exchange/#json-ld-framing-feature
	Frame interface{} `json:"frame,omitempty"`
}

func (pd *PresentationDefinition) IsEmpty() bool {
	if pd == nil {
		return true
	}
	return reflect.DeepEqual(pd, &PresentationDefinition{})
}

func (pd *PresentationDefinition) IsValid() error {
	if pd.IsEmpty() {
		return errors.New("presentation definition is empty")
	}
	if err := IsValidPresentationDefinition(*pd); err != nil {
		return errors.Wrap(err, "presentation definition failed json schema validation")
	}
	if len(pd.InputDescriptors) > 0 {
		for _, id := range pd.InputDescriptors {
			if err := id.IsValid(); err != nil {
				return errors.Wrap(err, "presentation definition's input descriptor failed json schema validation")
			}
		}
	}
	if pd.Format != nil {
		if err := IsValidFormatDeclaration(*pd.Format); err != nil {
			return errors.Wrap(err, "presentation definition's claim format failed json schema validation")
		}
	}
	if len(pd.SubmissionRequirements) > 0 {
		if err := AreValidSubmissionRequirements(pd.SubmissionRequirements); err != nil {
			return errors.Wrap(err, "presentation definition's submission requirements failed json schema validation")
		}
	}
	return util.NewValidator().Struct(pd)
}

// ClaimFormat https://identity.foundation/presentation-exchange/#claim-format-designations
// At most one field can have non-nil
type ClaimFormat struct {
	JWT   *JWTType `json:"jwt,omitempty" validate:"omitempty,dive"`
	JWTVC *JWTType `json:"jwt_vc,omitempty" validate:"omitempty,dive"`
	JWTVP *JWTType `json:"jwt_vp,omitempty" validate:"omitempty,dive"`

	LDP   *LDPType `json:"ldp,omitempty" validate:"omitempty,dive"`
	LDPVC *LDPType `json:"ldp_vc,omitempty" validate:"omitempty,dive"`
	LDPVP *LDPType `json:"ldp_vp,omitempty" validate:"omitempty,dive"`
}

// FormatValues return the string value of the associated claim format types
// NOTE: does not do error checking of any type.
func (cf ClaimFormat) FormatValues() []string {
	var res []string
	if cf.JWT != nil {
		res = append(res, string(JWT))
	}
	if cf.JWTVC != nil {
		res = append(res, string(JWTVC))
	}
	if cf.JWTVP != nil {
		res = append(res, string(JWTVP))
	}
	if cf.LDP != nil {
		res = append(res, string(LDP))
	}
	if cf.LDPVC != nil {
		res = append(res, string(LDPVC))
	}
	if cf.LDPVP != nil {
		res = append(res, string(LDPVP))
	}
	return res
}

// AlgOrProofTypePerFormat for a given format, return the supported alg or proof types. A nil response indicates
// that the format is not supported.
func (cf ClaimFormat) AlgOrProofTypePerFormat(format string) []string {
	var res []string
	if cf.JWT != nil {
		for _, a := range cf.JWT.Alg {
			res = append(res, string(a))
		}
	} else if cf.JWTVC != nil {
		for _, a := range cf.JWTVC.Alg {
			res = append(res, string(a))
		}
	} else if cf.JWTVP != nil {
		for _, a := range cf.JWTVP.Alg {
			res = append(res, string(a))
		}
	} else if cf.LDP != nil {
		for _, pt := range cf.LDP.ProofType {
			res = append(res, string(pt))
		}
	} else if cf.LDPVC != nil {
		for _, pt := range cf.LDPVC.ProofType {
			res = append(res, string(pt))
		}
	} else if cf.LDPVP != nil {
		for _, pt := range cf.LDPVP.ProofType {
			res = append(res, string(pt))
		}
	}
	return res
}

type JWTType struct {
	Alg []crypto.SignatureAlgorithm `json:"alg" validate:"required"`
}

type LDPType struct {
	ProofType []cryptosuite.SignatureType `json:"proof_type" validate:"required"`
}

type InputDescriptor struct {
	// Must be unique within the Presentation Definition
	ID   string `json:"id,omitempty" validate:"required,omitempty"`
	Name string `json:"name,omitempty"`
	// Purpose for which claim's data is being requested
	Purpose     string       `json:"purpose,omitempty"`
	Format      *ClaimFormat `json:"format,omitempty" validate:"omitempty,dive"`
	Constraints *Constraints `json:"constraints,omitempty"`
	// Must match a grouping strings listed in the `from` values of a submission requirement rule
	Group []string `json:"group,omitempty"`
}

func (id *InputDescriptor) IsEmpty() bool {
	if id == nil {
		return true
	}
	return reflect.DeepEqual(id, &InputDescriptor{})
}

func (id *InputDescriptor) IsValid() error {
	if id.IsEmpty() {
		return errors.New("input descriptor is empty")
	}
	if id.Format != nil {
		if err := IsValidFormatDeclaration(*id.Format); err != nil {
			return errors.Wrap(err, "input descriptor's claim format failed json schema validation")
		}
	}
	return util.NewValidator().Struct(id)
}

type Constraints struct {
	Fields          []Field     `json:"fields,omitempty"`
	LimitDisclosure *Preference `json:"limit_disclosure,omitempty"`

	// https://identity.foundation/presentation-exchange/#relational-constraint-feature
	SubjectIsIssuer *Preference           `json:"subject_is_issuer,omitempty"`
	IsHolder        *RelationalConstraint `json:"is_holder,omitempty" validate:"omitempty,dive"`
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
	FieldID   string      `json:"field_id" validate:"required"`
	Directive *Preference `json:"directive" validate:"required"`
}

type Filter struct {
	Type             string      `json:"type,omitempty"`
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
	AllOf         interface{}   `json:"allOf,omitempty"`
	OneOf         interface{}   `json:"oneOf,omitempty"`
}

// CredentialStatus https://identity.foundation/presentation-exchange/#credential-status-constraint-feature
type CredentialStatus struct {
	Active *struct {
		Directive Preference `json:"directive,omitempty"`
	} `json:"active,omitempty"`

	Suspended *struct {
		Directive Preference `json:"directive,omitempty"`
	} `json:"suspended,omitempty"`

	Revoked *struct {
		Directive Preference `json:"directive,omitempty"`
	} `json:"revoked,omitempty"`
}

// SubmissionRequirement https://identity.foundation/presentation-exchange/#presentation-definition-extensions
type SubmissionRequirement struct {
	Rule Selection `json:"rule" validate:"required"`
	// Either an array of SubmissionRequirement OR a string value
	FromOption `validate:"required"`

	Name    string `json:"name,omitempty"`
	Purpose string `json:"purpose,omitempty"`
	Count   int    `json:"count,omitempty" validate:"omitempty,min=1"`
	Minimum int    `json:"min,omitempty"`
	Maximum int    `json:"max,omitempty"`
}

func (sr *SubmissionRequirement) IsEmpty() bool {
	if sr == nil {
		return true
	}
	return reflect.DeepEqual(sr, &SubmissionRequirement{})
}

func (sr *SubmissionRequirement) IsValid() error {
	return util.NewValidator().Struct(sr)
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

func (ps *PresentationSubmission) IsEmpty() bool {
	if ps == nil {
		return true
	}
	return reflect.DeepEqual(ps, &PresentationSubmission{})
}

func (ps *PresentationSubmission) IsValid() error {
	return util.NewValidator().Struct(ps)
}

// SubmissionDescriptor is a mapping to Input Descriptor objects
type SubmissionDescriptor struct {
	// Must match the `id` property of the corresponding input descriptor
	ID         string                `json:"id" validate:"required"`
	Format     string                `json:"format" validate:"required"`
	Path       string                `json:"path" validate:"required"`
	PathNested *SubmissionDescriptor `json:"path_nested,omitempty"`
}

func (p Preference) ToPtr() *Preference {
	return &p
}
