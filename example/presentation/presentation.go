// A simple example of making a presentation request and a presentation definition with various comments.
// Please see the actual source code documentation for more detailed information and specifications
// for the specific methods. This is intended to give an overview and basic idea of how things work.

// |------------|       |----------------------|        |------------|
// |  Verifier   | ----> | Presentation Request | -----> |   Holder   |
// |            |       |      \Definition      |        |            |
// |------------|       |----------------------|        |------------|
package main

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/cryptosuite/jws2020"
	"github.com/goccy/go-json"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/example"
	"github.com/TBD54566975/ssi-sdk/util"
)

// Makes a dummy presentation definition. These are eventually transported via Presentation Request.
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
// A PR is sent by a verifier to a holder. It can be sent via multiple mechanisms
// For more information, please go to here:
// https://identity.foundation/presentation-exchange/#presentation-request
// and for the source code with the sdk,
// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/exchange/request.go
// is appropriate to start off with.
func makePresentationRequest(requesterID string, presentationData exchange.PresentationDefinition) ([]byte, error) {
	// Generate JSON Web Key
	// The JSONWebKey2020 type specifies a number of key type and curve pairs to enable JOSE conformance
	// https://w3c-ccg.github.io/lds-jws2020/#dfn-jsonwebkey2020
	jwk, err := jws2020.GenerateJSONWebKey2020(jws2020.OKP, jws2020.Ed25519)
	if err != nil {
		return nil, err
	}

	// Signer:
	// https://github.com/TBD54566975/ssi-sdk/blob/main/cryptosuite/jsonwebkey2020.go#L350
	// Implements: https://github.com/TBD54566975/ssi-sdk/blob/main/cryptosuite/jwt.go#L12
	signer, err := jwx.NewJWXSignerFromJWK(requesterID, jwk.PrivateKeyJWK)
	if err != nil {
		return nil, err
	}

	// Builds a presentation request
	// Requires a signer, the presentation data, and an optional audience
	audience := "did:test"
	requestJWTBytes, err := exchange.BuildJWTPresentationRequest(*signer, presentationData, []string{audience})
	if err != nil {
		return nil, err
	}

	// TODO: Add better documentation on the verification process
	// Seems like needed to know more of: https://github.com/lestrrat-go/jwx/tree/develop/v2/jwt
	verifier, err := jws2020.NewJSONWebKeyVerifier(audience, jwk.PublicKeyJWK)
	if err != nil {
		return nil, err
	}

	_, parsed, err := verifier.VerifyAndParse(string(requestJWTBytes))
	if err != nil {
		return nil, err
	}

	if dat, err := util.PrettyJSON(parsed); err == nil {
		fmt.Printf("Parsed Response:%s\n", string(dat))
	}

	return requestJWTBytes, err
}

func main() {
	data := makePresentationData()
	pr, err := makePresentationRequest("requester-id", data)
	example.HandleExampleError(err, "failed to make presentation request")
	dat, err := json.Marshal(pr)
	example.HandleExampleError(err, "failed to marshal presentation request")
	fmt.Printf("Presentation Request:\n%s", string(dat))
}
