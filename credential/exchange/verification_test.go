package exchange

import (
	"github.com/TBD54566975/did-sdk/credential/signing"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifyPresentationSubmission(t *testing.T) {
	t.Run("Unsupported embed target", func(tt *testing.T) {
		verifier := cryptosuite.JSONWebKeyVerifier{}
		err := VerifyPresentationSubmission(&verifier, "badEmbedTarget", PresentationDefinition{}, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported presentation submission embed target type")
	})

	t.Run("Supported embed target, bad submission", func(tt *testing.T) {
		jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
		assert.NoError(t, err)
		assert.NotEmpty(t, jwk)

		verifier, err := cryptosuite.NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
		assert.NoError(tt, err)

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
		err = VerifyPresentationSubmission(verifier, JWTVPTarget, def, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "verification of the presentation submission failed")
	})

	t.Run("Supported embed target, valid submission", func(tt *testing.T) {

	})
}

func TestVerifyPresentationSubmissionVP(t *testing.T) {
	t.Run("Simple verification", func(tt *testing.T) {
		jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
		assert.NoError(t, err)
		assert.NotEmpty(t, jwk)

		signer, err := cryptosuite.NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, cryptosuite.AssertionMethod)
		assert.NoError(t, err)

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
		submissionBytes, err := BuildPresentationSubmission(signer, def, []PresentationClaim{presentationClaim}, JWTVPTarget)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, submissionBytes)

		verifier, err := cryptosuite.NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
		assert.NoError(tt, err)
		vp, err := signing.VerifyVerifiablePresentationJWT(*verifier, string(submissionBytes))
		assert.NoError(tt, err)

		assert.NoError(tt, vp.IsValid())
		assert.Equal(tt, 1, len(vp.VerifiableCredential))
	})
}
