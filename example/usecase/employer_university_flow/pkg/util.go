package pkg

import (
	"fmt"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/example"
)

type Entity struct {
	wallet *example.SimpleWallet
	Name   string
}

func (e *Entity) GetWallet() *example.SimpleWallet {
	return e.wallet
}
func NewEntity(name string, keyType string) (*Entity, error) {
	e := Entity{
		wallet: example.NewSimpleWallet(),
		Name:   name,
	}
	if err := e.wallet.Init(keyType); err != nil {
		return nil, err
	}
	return &e, nil
}

// MakePresentationRequest Builds a presentation request (PR). A PR is sent by a holder to a verifier. It can be sent
// over multiple mechanisms. For more information, please go to here:
// https://identity.foundation/presentation-exchange/#presentation-request and for the source code with the sdk,
// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/exchange/request.go is appropriate to start off with.
func MakePresentationRequest(jwk cryptosuite.JSONWebKey2020, presentationData exchange.PresentationDefinition, requesterID, targetID string) (pr []byte, signer *crypto.JWTSigner, err error) {
	example.WriteNote("Presentation Request (JWT) is created")

	// Signer uses a JWK
	signer, err = crypto.NewJWTSignerFromJWK(requesterID, jwk.ID, jwk.PrivateKeyJWK)
	if err != nil {
		return nil, nil, err
	}

	// Builds a presentation request
	// Requires a signer, the presentation data, and a target which is the Audience Key
	requestJWTBytes, err := exchange.BuildJWTPresentationRequest(*signer, presentationData, targetID)
	if err != nil {
		return nil, nil, err
	}

	return requestJWTBytes, signer, err
}

// BuildPresentationSubmission builds a submission using...
// https://github.com/TBD54566975/ssi-sdk/blob/d279ca2779361091a70b8aa3c685a388067409a9/credential/exchange/submission.go#L126
func BuildPresentationSubmission(presentationRequestJWT string, signer crypto.JWTSigner, vc credential.VerifiableCredential) ([]byte, error) {
	presentationClaim := exchange.PresentationClaim{
		Credential:                    &vc,
		LDPFormat:                     exchange.LDPVC.Ptr(),
		SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
	}

	verifier, err := signer.ToVerifier(signer.ID)
	if err != nil {
		return nil, errors.Wrap(err, "creating verifier from signer")
	}
	_, parsedPresentationRequest, err := verifier.VerifyAndParse(presentationRequestJWT)
	if err != nil {
		return nil, err
	}

	def, ok := parsedPresentationRequest.Get(exchange.PresentationDefinitionKey)
	if !ok {
		return nil, fmt.Errorf("presentation definition key<%s> not found in token", exchange.PresentationDefinitionKey)
	}

	dat, err := json.Marshal(def)
	if err != nil {
		return nil, err
	}
	var pd exchange.PresentationDefinition
	if err = json.Unmarshal(dat, &pd); err != nil {
		return nil, err
	}

	submissionBytes, err := exchange.BuildPresentationSubmission(signer, parsedPresentationRequest.Issuer(), pd, []exchange.PresentationClaim{presentationClaim}, exchange.JWTVPTarget)
	if err != nil {
		return nil, err
	}

	return submissionBytes, nil
}

// MakePresentationData Makes a dummy presentation definition. These are eventually transported via Presentation Request.
// For more information on presentation definitions view the spec here:
// https://identity.foundation/presentation-exchange/#term:presentation-definition
func MakePresentationData(id string, inputID string) (exchange.PresentationDefinition, error) {
	// Input Descriptors: Describe the information the verifier requires of the holder
	// https://identity.foundation/presentation-exchange/#input-descriptor
	// Required fields: ID and Input Descriptors
	def := exchange.PresentationDefinition{
		ID: id,
		InputDescriptors: []exchange.InputDescriptor{
			{
				ID: inputID,
				Constraints: &exchange.Constraints{
					Fields: []exchange.Field{
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
	example.WriteNote("Presentation Definition is formed. Asks for the issuer and the data from the issuer")
	err := def.IsValid()
	return def, err
}
