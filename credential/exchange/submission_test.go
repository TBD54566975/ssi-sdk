//go:build jwx_es256k

package exchange

import (
	"github.com/TBD54566975/did-sdk/credential"
	"github.com/TBD54566975/did-sdk/crypto"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/TBD54566975/did-sdk/util"
	"github.com/oliveagle/jsonpath"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestBuildPresentationSubmission(t *testing.T) {

}

func TestBuildPresentationSubmissionVP(t *testing.T) {

}

func TestProcessInputDescriptor(t *testing.T) {
	t.Run("Simple Descriptor with One VC Claim", func(t *testing.T) {
		id := InputDescriptor{
			ID:          "id-1",
			Format:      nil,
			Constraints: nil,
		}
		assert.NotEmpty(t, id)
	})
}

func TestCanProcessDefinition(t *testing.T) {
	t.Run("With Submission Requirements", func(t *testing.T) {
		def := PresentationDefinition{
			ID: "submission-requirements",
			SubmissionRequirements: []SubmissionRequirement{{
				Rule: All,
				FromOption: FromOption{
					From: "A",
				},
			}},
		}
		err := canProcessDefinition(def)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "submission requirements feature not supported")
	})

	t.Run("With Predicates", func(t *testing.T) {
		def := PresentationDefinition{
			ID: "with-predicate",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-with-predicate",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Predicate: Allowed.ToPtr(),
							},
						},
					},
				},
			},
		}
		err := canProcessDefinition(def)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "predicate feature not supported")
	})

	t.Run("With Relational Constraint", func(t *testing.T) {
		def := PresentationDefinition{
			ID: "with-relational-constraint",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-with-relational-constraint",
					Constraints: &Constraints{
						IsHolder: &RelationalConstraint{
							FieldID:   "field-id",
							Directive: Allowed.ToPtr(),
						},
					},
				},
			},
		}
		err := canProcessDefinition(def)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "relational constraint feature not supported")
	})

	t.Run("With Credential Status", func(t *testing.T) {
		def := PresentationDefinition{
			ID: "with-credential-status",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-with-credential-status",
					Constraints: &Constraints{
						Statuses: &CredentialStatus{
							Active: &struct {
								Directive Preference `json:"directive,omitempty"`
							}{
								Directive: Required,
							},
						},
					},
				},
			},
		}
		err := canProcessDefinition(def)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credential status constraint feature not supported")
	})

	t.Run("With LD Framing", func(t *testing.T) {
		def := PresentationDefinition{
			ID:    "with-ld-framing",
			Frame: "@context",
		}
		err := canProcessDefinition(def)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "JSON-LD framing feature not supported")
	})
}

func TestConstructLimitedClaim(t *testing.T) {
	t.Run("Full Claim With Nesting", func(t *testing.T) {
		claim := getGenericTestClaim()
		var limitedDescriptors []limitedInputDescriptor

		typePath := "$.type"
		typeValue, err := jsonpath.JsonPathLookup(claim, typePath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: typePath,
			Data: typeValue,
		})

		issuerPath := "$.issuer"
		issuerValue, err := jsonpath.JsonPathLookup(claim, issuerPath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: issuerPath,
			Data: issuerValue,
		})

		idPath := "$.credentialSubject.id"
		idValue, err := jsonpath.JsonPathLookup(claim, idPath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: idPath,
			Data: idValue,
		})

		namePath := "$.credentialSubject.firstName"
		nameValue, err := jsonpath.JsonPathLookup(claim, namePath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: namePath,
			Data: nameValue,
		})

		favoritesPath := "$.credentialSubject.favorites.citiesByState.CA"
		favoritesValue, err := jsonpath.JsonPathLookup(claim, favoritesPath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: favoritesPath,
			Data: favoritesValue,
		})

		result, err := constructLimitedClaim(limitedDescriptors)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)

		issuerRes, ok := result["issuer"]
		assert.True(t, ok)
		assert.Equal(t, issuerRes, "did:example:123")

		credSubjRes, ok := result["credentialSubject"]
		assert.True(t, ok)

		id, ok := credSubjRes.(map[string]interface{})["id"]
		assert.True(t, ok)
		assert.Contains(t, id, "test-id")

		favoritesRes, ok := credSubjRes.(map[string]interface{})["favorites"]
		assert.True(t, ok)
		assert.NotEmpty(t, favoritesRes)

		statesRes, ok := favoritesRes.(map[string]interface{})["citiesByState"]
		assert.True(t, ok)
		assert.Contains(t, statesRes, "CA")

		citiesRes, ok := statesRes.(map[string]interface{})["CA"]
		assert.True(t, ok)
		assert.Contains(t, citiesRes, "Oakland")
	})

	t.Run("Complex Path Parsing", func(t *testing.T) {
		claim := getGenericTestClaim()
		var limitedDescriptors []limitedInputDescriptor

		filterPath := "$.credentialSubject.address[?(@.number > 0)]"
		filterValue, err := jsonpath.JsonPathLookup(claim, filterPath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: filterPath,
			Data: filterValue,
		})

		result, err := constructLimitedClaim(limitedDescriptors)
		assert.NoError(t, err)

		// make sure the result contains a value
		csValue, ok := result["credentialSubject"]
		assert.True(t, ok)
		assert.NotEmpty(t, csValue)

		addressValue, ok := csValue.(map[string]interface{})["address"]
		assert.True(t, ok)
		assert.Contains(t, addressValue, "road street")
		assert.Contains(t, addressValue, "USA")
	})
}

func getTestVerifiableCredential() credential.VerifiableCredential {
	return credential.VerifiableCredential{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		ID:           "test-verifiable-credential",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "test-issuer",
		IssuanceDate: "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{
			"id":      "test-vc-id",
			"company": "Block",
			"website": "https://block.xyz",
		},
	}
}

func getTestVerifiablePresentation() credential.VerifiablePresentation {
	return credential.VerifiablePresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		ID:      "test-verifiable-presentation",
		Type:    []string{"VerifiablePresentation"},
		VerifiableCredential: []interface{}{
			credential.VerifiableCredential{
				Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
					"https://w3id.org/security/suites/jws-2020/v1"},
				ID:           "test-vp-verifiable-credential",
				Type:         []string{"VerifiableCredential"},
				Issuer:       "test-issuer",
				IssuanceDate: "2021-01-01T19:23:24Z",
				CredentialSubject: map[string]interface{}{
					"id":      "test-vp-vc-id",
					"company": "TBD",
					"github":  "https://github.com/TBD54566975",
				},
			},
		},
	}
}

func TestNormalizePresentationClaims(t *testing.T) {
	t.Run("Normalize JWT Claim", func(tt *testing.T) {
		jwtVC := getTestJWTVerifiableCredential()
		assert.NotEmpty(tt, jwtVC)

		presentationClaim := PresentationClaim{
			Token:                         &jwtVC,
			JWTFormat:                     JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: string(crypto.EdDSA),
		}

		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NotEmpty(tt, normalized)
		assert.True(tt, len(normalized) == 1)
		assert.NotEmpty(tt, normalized[0].claimData)
		assert.EqualValues(tt, JWTVC, normalized[0].format)
		assert.EqualValues(tt, string(crypto.EdDSA), normalized[0].algOrProofType)
	})

	t.Run("Normalize VP Claim", func(tt *testing.T) {
		vpClaim := getTestVerifiablePresentation()
		assert.NotEmpty(tt, vpClaim)

		presentationClaim := PresentationClaim{
			Presentation:                  &vpClaim,
			LDPFormat:                     LDPVP.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}

		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NotEmpty(tt, normalized)
		assert.True(tt, len(normalized) == 1)
		assert.NotEmpty(tt, normalized[0].claimData)
		assert.EqualValues(tt, LDPVP, normalized[0].format)
		assert.EqualValues(tt, string(cryptosuite.JSONWebSignature2020), normalized[0].algOrProofType)
	})

	t.Run("Normalize VC Claim", func(tt *testing.T) {
		vcClaim := getTestVerifiableCredential()
		assert.NotEmpty(tt, vcClaim)

		presentationClaim := PresentationClaim{
			Credential:                    &vcClaim,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}

		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NotEmpty(tt, normalized)
		assert.True(tt, len(normalized) == 1)
		assert.NotEmpty(tt, normalized[0].claimData)
		assert.EqualValues(tt, LDPVC, normalized[0].format)
		assert.EqualValues(tt, string(cryptosuite.JSONWebSignature2020), normalized[0].algOrProofType)
	})
}

func getTestJWTVerifiableCredential() string {
	literalToken := `{
		"exp": 1925061804,
		"iss": "did:example:123",
		"nbf": 1609529004,
		"sub": "did:example:456",
		"vc": {
			"@context": [
				"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"
			],
			"credentialSubject": {
				"id": "did:example:456",
				"type": "Person"
			},
			"expirationDate": "2031-01-01T19:23:24Z",
			"issuanceDate": "2021-01-01T19:23:24Z",
			"issuer": "did:example:123",
			"type": ["VerifiableCredential"]
		}
	}`
	noNewLines := strings.ReplaceAll(literalToken, "\n", "")
	noTabs := strings.ReplaceAll(noNewLines, "\t", "")
	return strings.ReplaceAll(noTabs, " ", "")
}

func getGenericTestClaim() map[string]interface{} {
	return map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		"type":         []string{"VerifiableCredential"},
		"issuer":       "did:example:123",
		"issuanceDate": "2021-01-01T19:23:24Z",
		"credentialSubject": map[string]interface{}{
			"id":        "test-id",
			"firstName": "Satoshi",
			"lastName":  "Nakamoto",
			"address": map[string]interface{}{
				"number":  1,
				"street":  "road street",
				"country": "USA",
			},
			"favorites": map[string]interface{}{
				"color": "blue",
				"citiesByState": map[string]interface{}{
					"NY": []string{"NY"},
					"CA": []string{"Oakland", "San Francisco"},
				},
			},
		},
	}
}

func printerface(d interface{}) {
	b, _ := util.PrettyJSON(d)
	println(string(b))
}
