// A simple example of making a presentation request
// and a presentation definition with various comments.
// Please see the acutal source code documentation
// for more detialed information and specifications for the specific
// methods. This is intended to give an overview and basic
// idea of how things work.

//
// |------------|       |----------------------|        |------------|
// |  Verifier  | ----> | Presentation Request | -----> |   Holder   |
// |            |       |      \Definition     |        |            |
// |------------|       |----------------------|        |------------|
//
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/util"
)

// Makes a dummy presentation definition. These are
// eventually transported via Presentation Request.
// For more information on presentation definitions go
// https://identity.foundation/presentation-exchange/#term:presentation-definition
func makePresentationData() exchange.PresentationDefinition {
	// Input Descriptors: Describe the information the verifier requires of the holder
	// https://identity.foundation/presentation-exchange/#input-descriptor
	// Required fields: ID and Input Descriptors
	return exchange.PresentationDefinition{
		ID: "test-id",
		InputDescriptors: []exchange.InputDescriptor{
			{
				ID:      "test-input-descriptor-id",
				Name:    "test-input-descriptor",
				Purpose: "because!",
			},
		},
		Name: "test-def",
		Format: &exchange.ClaimFormat{ // Optional property
			JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
	}
}

// Build a presentation request (PR)
// A PR is sent by a verifier to a holder
// It can be sent over multiple mechanisms
// For more information, please go to here:
// https://identity.foundation/presentation-exchange/#presentation-request
// and for the source code with the sdk,
// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/exchange/request.go
// is appropriate to start off with.
func makePresentationRequest(presentationData exchange.PresentationDefinition) (pr []byte, err error) {

	// Generate JSON Web Key
	// The JSONWebKey2020 type specifies a number of key type and curve pairs to enable JOSE conformance
	// https://w3c-ccg.github.io/lds-jws2020/#dfn-jsonwebkey2020
	jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
	if err != nil {
		return
	}

	// Signer:
	// https://github.com/TBD54566975/ssi-sdk/blob/main/cryptosuite/jsonwebkey2020.go#L350
	// Implements: https://github.com/TBD54566975/ssi-sdk/blob/main/cryptosuite/jwt.go#L12
	signer, err := cryptosuite.NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, cryptosuite.Authentication)
	if err != nil {
		return
	}

	// Builds a presentation request
	// Requires a signeer, the presentation data, and the target
	// Target is the Audience Key
	requestJWTBytes, err := exchange.BuildJWTPresentationRequest(*signer, presentationData, "did:test")
	if err != nil {
		return
	}

	// TODO: Add better documentation on the verification prcoess
	// Seems like needed to know more of: https://github.com/lestrrat-go/jwx/tree/develop/v2/jwt
	verifier, err := cryptosuite.NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
	if err != nil {
		return
	}

	parsed, err := verifier.VerifyAndParseJWT(string(requestJWTBytes))
	if err != nil {
		return
	}

	if dat, err := util.PrettyJSON(parsed); err == nil {
		fmt.Printf("Parsed Response:%s\n", string(dat))
	}

	return requestJWTBytes, err
}

func handleError(err error, msg string) {
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("%s: %v", msg, err))
		os.Exit(1)
	}
}

func main() {
	data := makePresentationData()
	pr, err := makePresentationRequest(data)
	handleError(err, "faild to make presentation request")
	dat, err := json.Marshal(pr)
	handleError(err, "failed to marshal presentation request")
	fmt.Printf("Presentation Request:\n%s", string(dat))
}
