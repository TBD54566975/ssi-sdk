package exchange

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
)

func TestVerifyPresentationSubmission(t *testing.T) {
	t.Run("Unsupported embed target", func(tt *testing.T) {
		verifier := crypto.JWTVerifier{}
		err := VerifyPresentationSubmission(verifier, "badEmbedTarget", PresentationDefinition{}, nil)
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
		err := VerifyPresentationSubmission(*verifier, JWTVPTarget, def, nil)
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
		submissionBytes, err := BuildPresentationSubmission(*signer, def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		err = VerifyPresentationSubmission(*verifier, JWTVPTarget, def, submissionBytes)
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
		submissionBytes, err := BuildPresentationSubmission(*signer, def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		verifiablePresentation, err := signing.ParseVerifiablePresentationFromJWT(string(submissionBytes))
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
		vcData, err := signing.SignVerifiableCredentialJWT(*signer, testVC)
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
