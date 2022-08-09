// This is a full example flow of an apartment verifying the age of a potential tenant.

// The apartment will create a Presentation Request that is to be fulfilled by the tenant.
// The tenant will fulfil the Presentation Request by submitting a Presentation Submission.
// This presentation submission will contain a verifiable credential that has been previously issued and signed from the government issuer.

// The tenant will verify that the apartment's presentation request is valid and the apartment will also verify that the tenant's
// presentation submission is valid.

// At the end the apartment will verify the authenticity of the presentation submission and will be able to verify the birthdate of the tenant.

package main

import (
	"crypto/ed25519"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func main() {

	/**
		 Step 1: Create new entities as DIDs. Govt Issuer, User Holder, and Apartment Verifier
	**/

	// User Holder
	holderDIDPrivateKey, holderDIDKey, _ := did.GenerateDIDKey(crypto.Ed25519)
	holderJWK, _ := cryptosuite.JSONWebKey2020FromEd25519(holderDIDPrivateKey.(ed25519.PrivateKey))
	holderSigner, _ := cryptosuite.NewJSONWebKeySigner(holderJWK.ID, holderJWK.PrivateKeyJWK, cryptosuite.Authentication)
	holderVerifier, _ := cryptosuite.NewJSONWebKeyVerifier(holderJWK.ID, holderJWK.PublicKeyJWK)

	// Apt Verifier
	aptDidPrivateKey, aptDIDKey, _ := did.GenerateDIDKey(crypto.Ed25519)
	aptJWK, _ := cryptosuite.JSONWebKey2020FromEd25519(aptDidPrivateKey.(ed25519.PrivateKey))
	aptSigner, _ := cryptosuite.NewJSONWebKeySigner(aptJWK.ID, aptJWK.PrivateKeyJWK, cryptosuite.Authentication)
	aptVerifier, _ := cryptosuite.NewJSONWebKeyVerifier(aptJWK.ID, aptJWK.PublicKeyJWK)

	// Government Issuer
	govtDidPrivateKey, govtDIDKey, _ := did.GenerateDIDKey(crypto.Ed25519)
	govtJWK, _ := cryptosuite.JSONWebKey2020FromEd25519(govtDidPrivateKey.(ed25519.PrivateKey))
	govtSigner, _ := cryptosuite.NewJSONWebKeySigner(govtJWK.ID, govtJWK.PrivateKeyJWK, cryptosuite.Authentication)

	fmt.Print("\n\nStep 1: Create new DIDs for entities\n\n")
	fmt.Printf("Tenant: %s\n", string(*holderDIDKey))
	fmt.Printf("Apartment: %s\n", string(*aptDIDKey))
	fmt.Printf("Government: %s\n", string(*govtDIDKey))

	/**
		 Step 2: Government issuer issues credentials to holder claiming age. The government issuer then signs the verifiable credentials to holder claiming age
	**/

	knownIssuer := govtDIDKey
	knownIssuanceDate := "2020-01-01T19:23:24Z"
	knownSubject := map[string]interface{}{
		"id":        string(*holderDIDKey),
		"birthdate": "1975-01-01",
	}

	vcBuilder := credential.NewVerifiableCredentialBuilder()

	vcBuilder.SetIssuer(string(*knownIssuer))
	vcBuilder.SetIssuanceDate(knownIssuanceDate)
	vcBuilder.SetCredentialSubject(knownSubject)

	vc, _ := vcBuilder.Build()
	assert.NoError(nil, vc.IsValid())

	signedVCBytes, _ := signing.SignVerifiableCredentialJWT(*govtSigner, *vc)

	fmt.Print("\n\nStep 2: Government issues Verifiable Credential new for tenant verifying birthdate and signs\n\n")
	if dat, err := util.PrettyJSON(vc); err == nil {
		fmt.Printf("Verifiable Credential:%s\n", string(dat))
	}

	/**
		Step 3: Create presentation definition from the apartment to the holder which goes into a presentation request.
		The apartment is saying "here tenant, here is my what information I am requesting from you"
	**/

	presentationDefinitionBuilder := exchange.NewPresentationDefinitionBuilder()

	presentationDefinitionBuilder.SetInputDescriptors([]exchange.InputDescriptor{
		{
			ID:      "birthdate",
			Purpose: "Age verification",
			Format: &exchange.ClaimFormat{
				JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
			Constraints: &exchange.Constraints{Fields: []exchange.Field{
				{
					Path: []string{"$.credentialSubject.birthdate"},
					ID:   "birthdate",
				},
			}},
		},
	})

	presentationDefinition, _ := presentationDefinitionBuilder.Build()
	assert.NoError(nil, presentationDefinition.IsValid())

	presentationRequestBytes, _ := exchange.BuildPresentationRequest(aptSigner, exchange.JWTRequest, *presentationDefinition, string(*holderDIDKey))

	fmt.Print("\n\nStep 3: The apartment creates a presentation request that confirms which information is required from the tenant\n\n")
	if dat, err := util.PrettyJSON(presentationDefinition); err == nil {
		fmt.Printf("Presentation Definition that gets added to presentation request:%s\n", string(dat))
	}

	/**
		Step 4: Tenant holder verifies the presentation request from the apt is valid and then constructs and signs a presentation submission
	**/

	verifiedPresentationDefinition, err := exchange.VerifyPresentationRequest(aptVerifier, exchange.JWTRequest, presentationRequestBytes)
	assert.NoError(nil, verifiedPresentationDefinition.IsValid())

	// TODO: Have the presentation claim's token format support signedVCBytes for the BuildPresentationSubmission function
	testOutput, err := signing.ParseVerifiableCredentialFromJWT(string(signedVCBytes))
	testOutputBytes, _ := json.Marshal(testOutput)

	presentationClaim := exchange.PresentationClaim{
		Token:                         util.StringPtr(string(testOutputBytes)),
		JWTFormat:                     exchange.JWTVC.Ptr(),
		SignatureAlgorithmOrProofType: string(crypto.EdDSA),
	}

	presentationSubmissionBytes, _ := exchange.BuildPresentationSubmission(holderSigner, *presentationDefinition, []exchange.PresentationClaim{presentationClaim}, exchange.JWTVPTarget)

	fmt.Print("\n\nStep 4: The holder creates a presentation submission to give to the apartment\n\n")
	if dat, err := util.PrettyJSON(presentationClaim); err == nil {
		fmt.Printf("Presentation Claim that gets added to presentation submission:%s\n", string(dat))
	}

	/**
		Step 5: The apartment will verify the presentation submission. This is done to make sure the presentation is in compliance with the definition.
	**/

	err = exchange.VerifyPresentationSubmission(holderVerifier, exchange.JWTVPTarget, *presentationDefinition, presentationSubmissionBytes)
	assert.NoError(nil, err)

	fmt.Print("\n\nStep 5: The apartment verifies that the presentation submission is valid and then can cryptographically verify that the birthdate of the tenant is authentic\n\n")

	fmt.Print("\n\n\n🎉 The tenant's age has now been verified and can now move into the apartment! 🎉\n\n\n")
}
