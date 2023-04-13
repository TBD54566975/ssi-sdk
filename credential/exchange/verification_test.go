package exchange

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
)

func TestVerifyPresentationSubmission(t *testing.T) {
	t.Run("Unsupported embed target", func(tt *testing.T) {
		verifier := crypto.JWTVerifier{}
		err := VerifyPresentationSubmission(verifier, nil, "badEmbedTarget", PresentationDefinition{}, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported presentation submission embed target type")
	})

	t.Run("Supported embed target, bad submission", func(tt *testing.T) {
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
		_, verifier := getJWKSignerVerifier(tt)
		err := VerifyPresentationSubmission(*verifier, nil, JWTVPTarget, def, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "verification of the presentation submission failed")
	})

	t.Run("Supported embed target, valid submission", func(tt *testing.T) {
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
		submissionBytes, err := BuildPresentationSubmission(*signer, "requester", def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		err = VerifyPresentationSubmission(*verifier, nil, JWTVPTarget, def, submissionBytes)
		assert.NoError(tt, err)
	})
}

func TestVerifyPresentationSubmissionVP(t *testing.T) {
	t.Run("Simple verification", func(tt *testing.T) {
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

		signer, _ := getJWKSignerVerifier(tt)
		testVC := getTestVerifiableCredential()
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
		}
		submissionBytes, err := BuildPresentationSubmission(*signer, "requester", def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		_, _, verifiablePresentation, err := credential.ParseVerifiablePresentationFromJWT(string(submissionBytes))
		assert.NoError(tt, err)

		err = VerifyPresentationSubmissionVP(def, *verifiablePresentation)
		assert.NoError(tt, err)
	})

	t.Run("Missing Claim in Submission", func(tt *testing.T) {
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

		presentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1",
				"https://identity.foundation/presentation-exchange/submission/v1"},
			ID:   "55da1f5c-e2b3-443a-b687-0434712c5469",
			Type: []string{"VerifiablePresentation", "PresentationSubmission"},
			PresentationSubmission: PresentationSubmission{
				ID:           "45da2588-3637-45b0-84f1-17e97945ac09",
				DefinitionID: "test-id",
				DescriptorMap: []SubmissionDescriptor{
					{
						Format: "ldp_vc",
						ID:     "id-1",
						Path:   "$.verifiableCredential[0]",
					},
				},
			},
		}

		err := VerifyPresentationSubmissionVP(def, presentation)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not resolve claim from submission descriptor<id-1> with path: $.verifiableCredential[0]")
	})

	t.Run("Input Descriptor Not Fulfilled in Submission", func(tt *testing.T) {
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

		presentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1",
				"https://identity.foundation/presentation-exchange/submission/v1"},
			ID:   "55da1f5c-e2b3-443a-b687-0434712c5469",
			Type: []string{"VerifiablePresentation", "PresentationSubmission"},
			PresentationSubmission: PresentationSubmission{
				ID:           "45da2588-3637-45b0-84f1-17e97945ac09",
				DefinitionID: "test-id",
				DescriptorMap: []SubmissionDescriptor{
					{
						Format: "ldp_vc",
						ID:     "id-2",
						Path:   "$.verifiableCredential[0]",
					},
				},
			},
		}

		err := VerifyPresentationSubmissionVP(def, presentation)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unfulfilled input descriptor<id-1>; submission not valid")
	})

	t.Run("Input Descriptor with Bad Path", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$bad"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
							},
						},
					},
				},
			},
		}
		assert.NoError(tt, def.IsValid())

		presentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1",
				"https://identity.foundation/presentation-exchange/submission/v1"},
			ID:   "55da1f5c-e2b3-443a-b687-0434712c5469",
			Type: []string{"VerifiablePresentation", "PresentationSubmission"},
			PresentationSubmission: PresentationSubmission{
				ID:           "45da2588-3637-45b0-84f1-17e97945ac09",
				DefinitionID: "test-id",
				DescriptorMap: []SubmissionDescriptor{
					{
						Format: "ldp_vc",
						ID:     "id-1",
						Path:   "$.verifiableCredential[0]",
					},
				},
			},
			VerifiableCredential: []any{
				getTestVerifiableCredential(),
			},
		}

		err := VerifyPresentationSubmissionVP(def, presentation)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "matching path for claim could not be found")
	})

	t.Run("Input Descriptor with invalid and valid optional filter (test issuer)", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								ID:   "issuer-input-descriptor",
								Path: []string{"$.issuer"},
								Filter: &Filter{
									Type:    "string",
									Pattern: "not-test-issuer",
								},
								Optional: true,
							},
						},
					},
				},
			},
		}
		assert.NoError(tt, def.IsValid())

		presentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1",
				"https://identity.foundation/presentation-exchange/submission/v1"},
			ID:   "55da1f5c-e2b3-443a-b687-0434712c5469",
			Type: []string{"VerifiablePresentation", "PresentationSubmission"},
			PresentationSubmission: PresentationSubmission{
				ID:           "45da2588-3637-45b0-84f1-17e97945ac09",
				DefinitionID: "test-id",
				DescriptorMap: []SubmissionDescriptor{
					{
						Format: "ldp_vc",
						ID:     "id-1",
						Path:   "$.verifiableCredential[0]",
					},
				},
			},
			VerifiableCredential: []any{
				getTestVerifiableCredential(),
			},
		}

		err := VerifyPresentationSubmissionVP(def, presentation)
		assert.NoError(tt, err)

		// set optional flag to false and re-verify
		def.InputDescriptors[0].Constraints.Fields[0].Optional = false
		err = VerifyPresentationSubmissionVP(def, presentation)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unable to apply filter")
	})

	t.Run("Input Descriptor with subject == issuer constraint", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						SubjectIsIssuer: Required.Ptr(),
						Fields: []Field{
							{
								ID:   "issuer-input-descriptor",
								Path: []string{"$.issuer"},
								Filter: &Filter{
									Type:    "string",
									Pattern: "test-issuer",
								},
							},
						},
					},
				},
			},
		}
		assert.NoError(tt, def.IsValid())

		presentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1",
				"https://identity.foundation/presentation-exchange/submission/v1"},
			ID:   "55da1f5c-e2b3-443a-b687-0434712c5469",
			Type: []string{"VerifiablePresentation", "PresentationSubmission"},
			PresentationSubmission: PresentationSubmission{
				ID:           "45da2588-3637-45b0-84f1-17e97945ac09",
				DefinitionID: "test-id",
				DescriptorMap: []SubmissionDescriptor{
					{
						Format: "ldp_vc",
						ID:     "id-1",
						Path:   "$.verifiableCredential[0]",
					},
				},
			},
			VerifiableCredential: []any{
				getTestVerifiableCredential(),
			},
		}

		err := VerifyPresentationSubmissionVP(def, presentation)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "subject<test-vc-id> is not the same as issuer<test-issuer>")

		// modify the VC to have the same issuer and subject
		testVC := getTestVerifiableCredential()
		testVC.CredentialSubject[credential.VerifiableCredentialIDProperty] = "test-issuer"
		presentation.VerifiableCredential = []any{testVC}
		err = VerifyPresentationSubmissionVP(def, presentation)
		assert.NoError(tt, err)
	})

	t.Run("Input Descriptor with valid filter (credential properties)", func(tt *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								ID:   "issuer-input-descriptor",
								Path: []string{"$.issuer"},
								Filter: &Filter{
									Type:    "string",
									Pattern: "test-issuer",
								},
							},
							{
								ID:   "company-input-descriptor",
								Path: []string{"$.credentialSubject.company"},
								Filter: &Filter{
									Type:    "string",
									Pattern: "Block",
								},
							},
						},
					},
				},
			},
		}
		assert.NoError(tt, def.IsValid())

		presentation := credential.VerifiablePresentation{
			Context: []string{"https://www.w3.org/2018/credentials/v1",
				"https://identity.foundation/presentation-exchange/submission/v1"},
			ID:   "55da1f5c-e2b3-443a-b687-0434712c5469",
			Type: []string{"VerifiablePresentation", "PresentationSubmission"},
			PresentationSubmission: PresentationSubmission{
				ID:           "45da2588-3637-45b0-84f1-17e97945ac09",
				DefinitionID: "test-id",
				DescriptorMap: []SubmissionDescriptor{
					{
						Format: "ldp_vc",
						ID:     "id-1",
						Path:   "$.verifiableCredential[0]",
					},
				},
			},
			VerifiableCredential: []any{
				getTestVerifiableCredential(),
			},
		}

		err := VerifyPresentationSubmissionVP(def, presentation)
		assert.NoError(tt, err)
	})

	t.Run("Verification with JWT credential", func(t *testing.T) {
		def := PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []InputDescriptor{
				{
					ID: "id-1",
					Constraints: &Constraints{
						Fields: []Field{
							{
								Path:    []string{"$.vc.credentialSubject.company", "$.credentialSubject.company"},
								ID:      "works-for-block",
								Purpose: "need to check the company of the subject",
							},
						},
					},
				},
			},
		}
		signer, _ := getJWKSignerVerifier(t)
		testVC := getTestVerifiableCredential()
		vcData, err := credential.SignVerifiableCredentialJWT(*signer, testVC)
		assert.NoError(t, err)
		b := NewPresentationSubmissionBuilder(def.ID)
		assert.NoError(t, b.SetDescriptorMap([]SubmissionDescriptor{
			{
				ID:         "id-1",
				Format:     string(JWTVPTarget),
				Path:       "$.verifiableCredential[0]",
				PathNested: nil,
			},
		}))
		ps, err := b.Build()
		assert.NoError(t, err)

		vpBuilder := credential.NewVerifiablePresentationBuilder()
		assert.NoError(t, vpBuilder.SetPresentationSubmission(ps))
		assert.NoError(t, vpBuilder.AddVerifiableCredentials([]any{string(vcData)}...))
		vp2, err := vpBuilder.Build()
		assert.NoError(t, err)
		vp := *vp2

		assert.NoError(t, VerifyPresentationSubmissionVP(def, vp))
	})
}
