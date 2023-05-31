package exchange

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/cryptosuite/jws2020"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/util"

	"github.com/TBD54566975/ssi-sdk/credential"
)

func TestVerifyPresentationSubmission(t *testing.T) {
	t.Run("Empty submission", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		verifier := jwx.Verifier{}
		_, err = VerifyPresentationSubmission(context.Background(), verifier, resolver, "badEmbedTarget", PresentationDefinition{}, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "submission cannot be empty")
	})

	t.Run("Empty presentation definition", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		verifier := jwx.Verifier{}
		_, err = VerifyPresentationSubmission(context.Background(), verifier, resolver, "badEmbedTarget", PresentationDefinition{}, []byte{0, 1, 2, 3})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "presentation definition cannot be empty")
	})

	t.Run("Unsupported embed target", func(tt *testing.T) {
		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		verifier := jwx.Verifier{}
		_, err = VerifyPresentationSubmission(context.Background(), verifier, resolver, "badEmbedTarget", PresentationDefinition{ID: "1"}, []byte{0, 1, 2, 3})
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

		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)
		_, verifier := getJWKSignerVerifier(tt)
		_, err = VerifyPresentationSubmission(context.Background(), *verifier, resolver, JWTVPTarget, def, []byte{0, 1, 2, 3})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "verification of the presentation submission failed")
	})

	t.Run("Supported embed target, valid submission, invalid credential format", func(tt *testing.T) {
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

		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		signer, verifier := getJWKSignerVerifier(tt)
		testVC := getTestVerifiableCredential(signer.ID, signer.ID)
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		submissionBytes, err := BuildPresentationSubmission(*signer, verifier.ID, def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		_, err = VerifyPresentationSubmission(context.Background(), *verifier, resolver, JWTVPTarget, def, submissionBytes)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential must have a proof")
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

		resolver, err := resolution.NewResolver([]resolution.Resolver{key.Resolver{}}...)
		assert.NoError(tt, err)

		signer, verifier := getJWKSignerVerifier(tt)
		testVC := getTestVerifiableCredential(signer.ID, signer.ID)
		credJWT, err := credential.SignVerifiableCredentialJWT(*signer, testVC)
		assert.NoError(tt, err)
		presentationClaim := PresentationClaim{
			Token:                         util.StringPtr(string(credJWT)),
			JWTFormat:                     JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: signer.ALG,
		}
		submissionBytes, err := BuildPresentationSubmission(*signer, verifier.ID, def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		_, err = VerifyPresentationSubmission(context.Background(), *verifier, resolver, JWTVPTarget, def, submissionBytes)
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
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		presentationClaim := PresentationClaim{
			Credential:                    &testVC,
			LDPFormat:                     LDPVC.Ptr(),
			SignatureAlgorithmOrProofType: string(jws2020.JSONWebSignature2020),
		}
		submissionBytes, err := BuildPresentationSubmission(*signer, "requester", def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		_, _, verifiablePresentation, err := credential.ParseVerifiablePresentationFromJWT(string(submissionBytes))
		assert.NoError(tt, err)

		_, err = VerifyPresentationSubmissionVP(def, *verifiablePresentation)
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

		_, err := VerifyPresentationSubmissionVP(def, presentation)
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

		_, err := VerifyPresentationSubmissionVP(def, presentation)
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
				getTestVerifiableCredential("test-issuer", "test-subject"),
			},
		}

		_, err := VerifyPresentationSubmissionVP(def, presentation)
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
				getTestVerifiableCredential("test-issuer", "test-subject"),
			},
		}

		verifiedSubmissionData, err := VerifyPresentationSubmissionVP(def, presentation)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedSubmissionData)
		assert.Equal(tt, 1, len(verifiedSubmissionData))
		assert.Equal(tt, "id-1", verifiedSubmissionData[0].InputDescriptorID)
		assert.Equal(tt, "test-issuer", verifiedSubmissionData[0].FilteredData)

		// set optional flag to false and re-verify
		def.InputDescriptors[0].Constraints.Fields[0].Optional = false
		_, err = VerifyPresentationSubmissionVP(def, presentation)
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
				getTestVerifiableCredential("test-issuer", "test-subject"),
			},
		}

		_, err := VerifyPresentationSubmissionVP(def, presentation)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "subject<test-subject> is not the same as issuer<test-issuer>")

		// modify the VC to have the same issuer and subject
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		testVC.CredentialSubject[credential.VerifiableCredentialIDProperty] = "test-issuer"
		presentation.VerifiableCredential = []any{testVC}

		verifiedSubmissionData, err := VerifyPresentationSubmissionVP(def, presentation)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedSubmissionData)
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
				getTestVerifiableCredential("test-issuer", "test-subject"),
			},
		}

		verifiedSubmissionData, err := VerifyPresentationSubmissionVP(def, presentation)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedSubmissionData)
		assert.Equal(tt, 1, len(verifiedSubmissionData))
		assert.Equal(tt, "id-1", verifiedSubmissionData[0].InputDescriptorID)
		assert.Equal(tt, "Block", verifiedSubmissionData[0].FilteredData)
	})

	t.Run("Verification with JWT credential", func(tt *testing.T) {
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
		signer, _ := getJWKSignerVerifier(tt)
		testVC := getTestVerifiableCredential("test-issuer", "test-subject")
		vcData, err := credential.SignVerifiableCredentialJWT(*signer, testVC)
		assert.NoError(tt, err)
		b := NewPresentationSubmissionBuilder(def.ID)
		assert.NoError(tt, b.SetDescriptorMap([]SubmissionDescriptor{
			{
				ID:         "id-1",
				Format:     string(JWTVPTarget),
				Path:       "$.verifiableCredential[0]",
				PathNested: nil,
			},
		}))
		ps, err := b.Build()
		assert.NoError(tt, err)

		vpBuilder := credential.NewVerifiablePresentationBuilder()
		assert.NoError(tt, vpBuilder.SetPresentationSubmission(ps))
		assert.NoError(tt, vpBuilder.AddVerifiableCredentials([]any{string(vcData)}...))
		vp2, err := vpBuilder.Build()
		assert.NoError(tt, err)
		vp := *vp2

		verifiedSubmissionData, err := VerifyPresentationSubmissionVP(def, vp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedSubmissionData)
	})
}
