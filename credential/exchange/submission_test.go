package exchange

import (
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
)

func TestBuildPresentationSubmission(t *testing.T) {
	t.Run("Unsupported embed target", func(tt *testing.T) {
		_, err := BuildPresentationSubmission(&cryptosuite.JSONWebKeySigner{}, PresentationDefinition{}, nil, "badEmbedTarget")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported presentation submission embed target type")
	})

	t.Run("Supported embed target", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
							},
						},
					},
				},
			},
		}
		assert.NoError(tt, def.IsValid())

		signer, verifier := getJWKSignerVerifier(tt)
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		submissionBytes, err := BuildPresentationSubmission(signer, def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		vp, err := signing.VerifyVerifiablePresentationJWT(*verifier, string(submissionBytes))
		assert.NoError(tt, err)

		assert.NoError(tt, vp.IsValid())
		assert.Equal(tt, 1, len(vp.VerifiableCredential))
	})
}

func TestBuildPresentationSubmissionVP(t *testing.T) {
	t.Run("Single input descriptor definition with single claim", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
							},
						},
					},
				},
			},
		}

		assert.NoError(tt, def.IsValid())
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		vp, err := BuildPresentationSubmissionVP(def, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, vp)

		// validate the submission is properly constructed
		assert.NotEmpty(tt, vp.PresentationSubmission)
		asSubmission, ok := vp.PresentationSubmission.(PresentationSubmission)
		assert.True(tt, ok)
		assert.NoError(tt, asSubmission.IsValid())
		assert.Equal(tt, def.ID, asSubmission.DefinitionID)
		assert.Equal(tt, 1, len(asSubmission.DescriptorMap))
		assert.Equal(tt, def.InputDescriptors[0].ID, asSubmission.DescriptorMap[0].ID)
		assert.EqualValues(tt, LDPVC, asSubmission.DescriptorMap[0].Format)

		// validate the vc result exists in the VP
		assert.Equal(tt, 1, len(vp.VerifiableCredential))
		vcBytes, err := json.Marshal(vp.VerifiableCredential[0])
		assert.NoError(tt, err)
		var asVC credential.VerifiableCredential
		err = json.Unmarshal(vcBytes, &asVC)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, asVC)

		assert.Equal(tt, "test-verifiable-credential", asVC.ID)
		assert.Equal(tt, "Block", asVC.CredentialSubject["company"])
	})

	t.Run("Single input descriptor definition with no matching claims", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
							},
						},
					},
				},
			},
		}

		assert.NoError(tt, def.IsValid())
		vp, err := BuildPresentationSubmissionVP(def, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "no claims match the required format, and signing alg/proof type requirements for input descriptor")
		assert.Empty(tt, vp)
	})

	t.Run("Two input descriptors with single claim that matches both", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
							},
						},
					},
				},
				{
					ID: "id-2",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.id", "$.id"},
								ID:      "id-input-descriptor",
								Purpose: "need to check the id",
							},
						},
					},
				},
			},
		}

		assert.NoError(tt, def.IsValid())
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		vp, err := BuildPresentationSubmissionVP(def, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, vp)

		// validate the submission is properly constructed
		assert.NotEmpty(tt, vp.PresentationSubmission)
		asSubmission, ok := vp.PresentationSubmission.(PresentationSubmission)
		assert.True(tt, ok)
		assert.NoError(tt, asSubmission.IsValid())
		assert.Equal(tt, def.ID, asSubmission.DefinitionID)
		assert.Equal(tt, 2, len(asSubmission.DescriptorMap))
		assert.Equal(tt, def.InputDescriptors[0].ID, asSubmission.DescriptorMap[0].ID)
		assert.EqualValues(tt, LDPVC, asSubmission.DescriptorMap[0].Format)

		// validate the vc result exists in the VP
		assert.Equal(tt, 1, len(vp.VerifiableCredential))
		vcBytes, err := json.Marshal(vp.VerifiableCredential[0])
		assert.NoError(tt, err)
		var asVC credential.VerifiableCredential
		err = json.Unmarshal(vcBytes, &asVC)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, asVC)

		assert.Equal(tt, "test-verifiable-credential", asVC.ID)
		assert.Equal(tt, "Block", asVC.CredentialSubject["company"])
	})

	t.Run("Two input descriptors with two claims that match one input descriptor", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
							},
						},
					},
				},
				{
					ID: "id-2",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.credentialSubject.color"},
								ID:      "color-input-descriptor",
								Purpose: "need to check the color",
							},
						},
					},
				},
			},
		}

		assert.NoError(tt, def.IsValid())
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		testVCJWT := getTestJWTVerifiableCredential()
		presentationClaimJWT := PresentationClaim{
			TokenJSON:                     &testVCJWT,
			JWTFormat:                     JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: string(crypto.EdDSA),
		}

		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim, presentationClaimJWT})
		vp, err := BuildPresentationSubmissionVP(def, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, vp)

		// validate the submission is properly constructed
		assert.NotEmpty(tt, vp.PresentationSubmission)
		asSubmission, ok := vp.PresentationSubmission.(PresentationSubmission)
		assert.True(tt, ok)
		assert.NoError(tt, asSubmission.IsValid())
		assert.Equal(tt, def.ID, asSubmission.DefinitionID)
		assert.Equal(tt, 2, len(asSubmission.DescriptorMap))
		assert.Equal(tt, def.InputDescriptors[0].ID, asSubmission.DescriptorMap[0].ID)
		assert.EqualValues(tt, LDPVC, asSubmission.DescriptorMap[0].Format)

		// validate the vc result exists in the VP
		assert.Equal(tt, 2, len(vp.VerifiableCredential))
		vcBytes, err := json.Marshal(vp.VerifiableCredential[0])
		assert.NoError(tt, err)
		var asVC credential.VerifiableCredential
		err = json.Unmarshal(vcBytes, &asVC)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, asVC)

		assert.Equal(tt, "test-verifiable-credential", asVC.ID)
		assert.Equal(tt, "Block", asVC.CredentialSubject["company"])

		vcBytesJWT, err := json.Marshal(vp.VerifiableCredential[1])
		assert.NoError(tt, err)
		var asVCJWT map[string]interface{}
		err = json.Unmarshal(vcBytesJWT, &asVCJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, asVCJWT)

		assert.Equal(tt, "did:example:456", asVCJWT["sub"])
		assert.Equal(tt, "yellow", asVCJWT["vc"].(map[string]interface{})["credentialSubject"].(map[string]interface{})["color"])
	})
}

func TestProcessInputDescriptor(t *testing.T) {
	t.Run("Simple Descriptor with One VC Claim", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				Fields: []Field{
					{
						Path:    []string{"$.vc.issuer", "$.issuer"},
						ID:      "issuer-input-descriptor",
						Purpose: "need to check the issuer",
					},
				},
			},
		}
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		processed, err := processInputDescriptor(id, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, processed)
		assert.Equal(tt, id.ID, processed.ID)

		// make sure it's not limited disclosure
		assert.Equal(tt, "test-verifiable-credential", processed.Claim["id"])
	})

	t.Run("Simple Descriptor with One VC Claim and Limited Disclosure", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				LimitDisclosure: Required.Ptr(),
				Fields: []Field{
					{
						Path:    []string{"$.vc.issuer", "$.issuer"},
						ID:      "issuer-input-descriptor",
						Purpose: "need to check the issuer",
					},
				},
			},
		}
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		processed, err := processInputDescriptor(id, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, processed)
		assert.Equal(tt, id.ID, processed.ID)

		// make sure it's limited disclosure
		assert.NotEqual(tt, "test-verifiable-credential", processed.Claim["id"])
	})

	t.Run("Descriptor with no matching paths", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				LimitDisclosure: Required.Ptr(),
				Fields: []Field{
					{
						Path:    []string{"$.vc.issuer"},
						ID:      "issuer-input-descriptor",
						Purpose: "need to check the issuer",
					},
				},
			},
		}
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		_, err := processInputDescriptor(id, normalized)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "no claims could fulfill the input descriptor")
	})

	t.Run("Descriptor with no matching format", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				LimitDisclosure: Required.Ptr(),
				Fields: []Field{
					{
						Path:    []string{"$.issuer"},
						ID:      "issuer-input-descriptor",
						Purpose: "need to check the issuer",
					},
				},
			},
			Format: &ClaimFormat{
				LDP: &LDPType{
					ProofType: []cryptosuite.SignatureType{cryptosuite.JSONWebSignature2020},
				},
			},
		}
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		_, err := processInputDescriptor(id, normalized)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "no claims match the required format, and signing alg/proof type requirements")
	})

	t.Run("Descriptor with matching format", func(tt *testing.T) {
		id := InputDescriptor{
			ID: "id-1",
			Constraints: &Constraints{
				LimitDisclosure: Required.Ptr(),
				Fields: []Field{
					{
						Path:    []string{"$.issuer"},
						ID:      "issuer-input-descriptor",
						Purpose: "need to check the issuer",
					},
				},
			},
			Format: &ClaimFormat{
				LDPVC: &LDPType{
					ProofType: []cryptosuite.SignatureType{cryptosuite.JSONWebSignature2020},
				},
			},
		}
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		processed, err := processInputDescriptor(id, normalized)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, processed)
		assert.Equal(tt, id.ID, processed.ID)
	})
}

func TestCanProcessDefinition(tt *testing.T) {
	tt.Run("With Submission Requirements", func(t *testing.T) {
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

	tt.Run("With Predicates", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "with-predicate",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-with-predicate",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Predicate: Allowed.Ptr(),
							},
						},
					},
				},
			},
		}
		err := canProcessDefinition(def)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "predicate feature not supported")
	})

	tt.Run("With Relational Constraint", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "with-relational-constraint",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-with-relational-constraint",
					Constraints: &Constraints{
						IsHolder: &RelationalConstraint{
							FieldID:   "field-id",
							Directive: Allowed.Ptr(),
						},
					},
				},
			},
		}
		err := canProcessDefinition(def)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "relational constraint feature not supported")
	})

	tt.Run("With Credential Status", func(tt *testing.T) {
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
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential status constraint feature not supported")
	})

	tt.Run("With LD Framing", func(t *testing.T) {
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
	t.Run("Full Claim With Nesting", func(tt *testing.T) {
		claim := getGenericTestClaim()
		var limitedDescriptors []limitedInputDescriptor

		typePath := "$.type"
		typeValue, err := jsonpath.JsonPathLookup(claim, typePath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: typePath,
			Data: typeValue,
		})

		issuerPath := "$.issuer"
		issuerValue, err := jsonpath.JsonPathLookup(claim, issuerPath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: issuerPath,
			Data: issuerValue,
		})

		idPath := "$.credentialSubject.id"
		idValue, err := jsonpath.JsonPathLookup(claim, idPath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: idPath,
			Data: idValue,
		})

		namePath := "$.credentialSubject.firstName"
		nameValue, err := jsonpath.JsonPathLookup(claim, namePath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: namePath,
			Data: nameValue,
		})

		favoritesPath := "$.credentialSubject.favorites.citiesByState.CA"
		favoritesValue, err := jsonpath.JsonPathLookup(claim, favoritesPath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: favoritesPath,
			Data: favoritesValue,
		})

		result := constructLimitedClaim(limitedDescriptors)
		assert.NotEmpty(tt, result)

		issuerRes, ok := result["issuer"]
		assert.True(tt, ok)
		assert.Equal(tt, issuerRes, "did:example:123")

		credSubjRes, ok := result["credentialSubject"]
		assert.True(tt, ok)

		id, ok := credSubjRes.(map[string]interface{})["id"]
		assert.True(tt, ok)
		assert.Contains(tt, id, "test-id")

		favoritesRes, ok := credSubjRes.(map[string]interface{})["favorites"]
		assert.True(tt, ok)
		assert.NotEmpty(tt, favoritesRes)

		statesRes, ok := favoritesRes.(map[string]interface{})["citiesByState"]
		assert.True(tt, ok)
		assert.Contains(tt, statesRes, "CA")

		citiesRes, ok := statesRes.(map[string]interface{})["CA"]
		assert.True(tt, ok)
		assert.Contains(tt, citiesRes, "Oakland")
	})

	t.Run("Complex Path Parsing", func(tt *testing.T) {
		claim := getGenericTestClaim()
		var limitedDescriptors []limitedInputDescriptor

		filterPath := "$.credentialSubject.address[?(@.number > 0)]"
		filterValue, err := jsonpath.JsonPathLookup(claim, filterPath)
		assert.NoError(tt, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: filterPath,
			Data: filterValue,
		})

		result := constructLimitedClaim(limitedDescriptors)
		assert.NotEmpty(tt, result)

		// make sure the result contains a value
		csValue, ok := result["credentialSubject"]
		assert.True(tt, ok)
		assert.NotEmpty(tt, csValue)

		addressValue, ok := csValue.(map[string]interface{})["address"]
		assert.True(tt, ok)
		assert.Contains(tt, addressValue, "road street")
		assert.Contains(tt, addressValue, "USA")
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
			TokenJSON:                     &jwtVC,
			JWTFormat:                     JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: string(crypto.EdDSA),
		}

		normalized := normalizePresentationClaims([]PresentationClaim{presentationClaim})
		assert.NotEmpty(tt, normalized)
		assert.True(tt, len(normalized) == 1)
		assert.NotEmpty(tt, normalized[0].Data)
		assert.EqualValues(tt, JWTVC, normalized[0].Format)
		assert.EqualValues(tt, string(crypto.EdDSA), normalized[0].AlgOrProofType)
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
		assert.NotEmpty(tt, normalized[0].Data)
		assert.EqualValues(tt, LDPVP, normalized[0].Format)
		assert.EqualValues(tt, string(cryptosuite.JSONWebSignature2020), normalized[0].AlgOrProofType)
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
		assert.NotEmpty(tt, normalized[0].Data)
		assert.EqualValues(tt, LDPVC, normalized[0].Format)
		assert.EqualValues(tt, string(cryptosuite.JSONWebSignature2020), normalized[0].AlgOrProofType)
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
				"color": "yellow"
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

func getJWKSignerVerifier(t *testing.T) (*cryptosuite.JSONWebKeySigner, *cryptosuite.JSONWebKeyVerifier) {
	jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, jwk)

	signer, err := cryptosuite.NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, cryptosuite.AssertionMethod)
	assert.NoError(t, err)

	verifier, err := cryptosuite.NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
	assert.NoError(t, err)

	return signer, verifier
}
