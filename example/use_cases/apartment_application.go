// A full flow example of making a presentation request and a presentation definition with various comments.
//
// A full example flow of  apartment wants to verify the age of a new potential tenant. The apartment will create a presentationDefinition which goes into a presentationRequest.
// The tenant will fulfil the presentationRequest by submitting a presentationSubmission. This presentation submissioon will have a verifiable credential
// issued from the goverment issuer.

package main

import (
	"crypto/ed25519"
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
)

func main() {

	/**
		 Step 1: Create new new DIDS. Govt Issuer, User Holder, and Apartment Verifier
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

	// Govt Issuer
	govtDidPrivateKey, govtDIDKey, _ := did.GenerateDIDKey(crypto.Ed25519)
	govtJWK, _ := cryptosuite.JSONWebKey2020FromEd25519(govtDidPrivateKey.(ed25519.PrivateKey))
	govtSigner, _ := cryptosuite.NewJSONWebKeySigner(govtJWK.ID, govtJWK.PrivateKeyJWK, cryptosuite.Authentication)
	govtVerifier, _ := cryptosuite.NewJSONWebKeyVerifier(govtJWK.ID, govtJWK.PublicKeyJWK)

	/**
		 Step 2: Govt issuer issues credentials to holder claiming age
	**/

	knownIssuer := govtDIDKey
	knownIssuanceDate := "2020-01-01T19:23:24Z"
	knownSubject := map[string]interface{}{
		"id":        string(*holderDIDKey),
		"birthdate": "1975-01-01",
	}

	vcBuilder := credential.NewVerifiableCredentialBuilder()

	err := vcBuilder.SetIssuer(string(*knownIssuer))

	if err != nil {
		print("set issuer error")
		return
	}
	vcBuilder.SetIssuanceDate(knownIssuanceDate)
	vcBuilder.SetCredentialSubject(knownSubject)

	vc, _ := vcBuilder.Build()

	err = vc.IsValid()
	if err != nil {
		print("vc is not valid")
		return
	}

	/**
		 Step 3: Govt issuer signs credentials to holder claiming age
	**/

	signedVCBytes, _ := signing.SignVerifiableCredentialJWT(*govtSigner, *vc)

	/**
		Step 4: Create presentationDefinition from the apartment to the holder which goes into a presentation request. To say "here holder, here is my request for the info"
	**/

	presentationDefinitionBuilder := exchange.NewPresentationDefinitionBuilder()

	presentationDefinitionBuilder.SetInputDescriptors([]exchange.InputDescriptor{
		{
			ID:      "birthdate",
			Purpose: "Age verification",
			Format: &exchange.ClaimFormat{
				JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
		},
	})

	presentationDefinition, _ := presentationDefinitionBuilder.Build()

	presentationRequestBytes, _ := exchange.BuildPresentationRequest(aptSigner, exchange.JWTRequest, *presentationDefinition, string(*holderDIDKey))

	/**
		Step 5: holder verifies the presentation request from the apt is valid and then constructs and signs a presentation submission
	**/

	verifiedPresentationDefinition, err := exchange.VerifyPresentationRequest(aptVerifier, exchange.JWTRequest, presentationRequestBytes)
	if err != nil {
		print("set issuer error")
		print(verifiedPresentationDefinition)
		return
	}

	testOutput, err := signing.ParseVerifiableCredentialFromJWT(string(signedVCBytes))

	print(testOutput)
	testOutputBytes, _ := json.Marshal(testOutput)

	presentationClaim := exchange.PresentationClaim{
		Token:     util.StringPtr(string(testOutputBytes)),
		JWTFormat: exchange.JWTVC.Ptr(),
	}

	// TODO:
	presentationSubmissionBytes, err := exchange.BuildPresentationSubmission(holderSigner, *presentationDefinition, []exchange.PresentationClaim{presentationClaim}, exchange.JWTVPTarget)

	if err != nil {
		print(err)
		return
	}

	/**
		Step 6: Verifyer will Verify the presentation submission. * Need to make sure the presentation compliances with the definition.
	**/

	// Todo: Correct verifier and parameters?
	exchange.VerifyPresentationSubmission(aptVerifier, exchange.JWTVPTarget, *presentationDefinition, nil)

	print(holderVerifier)
	print(aptDIDKey)
	print(govtVerifier)
	print(signedVCBytes)
	//print(presentationRequestJWTBytes)
	print(presentationSubmissionBytes)

}
