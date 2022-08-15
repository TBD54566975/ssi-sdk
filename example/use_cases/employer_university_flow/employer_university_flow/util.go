package employer_university_flow

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/sirupsen/logrus"
)

var cw = CustomStepWriter{}

var (
	UnsupportedDIDErorr = errors.New("unsupported Method for DID")
)

// Resolves a DID
// Right the current implementation ssk-sdk does
// not have a universal resolver.
// https://github.com/decentralized-identity/universal-resolver
// is a case where a universal resolver is implemented,
// but the resolution would need to be hooked with the sdk.
//  TODO (andor): Should exist a universal resolution method somewhere
// in the actual SDK
func resolveDID(didStr string) (*did.DIDDocument, error) {
	split := strings.Split(string(didStr), ":")
	if len(split) < 2 {
		return nil, errors.New("invalid DID. Does not split correctly")
	}
	var method = split[1]
	switch method {
	case did.DIDKeyPrefix:
		return did.DIDKey(didStr).Expand()
	case did.DIDWebPrefix:
		return did.DIDWeb(didStr).Resolve()
	case did.PeerMethodPrefix:
		did, _, _, err := did.DIDPeer(didStr).Resolve()
		return did, err
	default:
		return nil, fmt.Errorf("%v. Got %v method", UnsupportedDIDErorr, method)
	}
}

// Color coding to make it easier to read terminal
const (
	NoteColor   = "\033[1;34m%s\033[0m"
	ActionColor = "\033[1;36m%s\033[0m"
	StepColor   = "\033[1;33m%s\033[0m"
	ErrorColor  = "\033[1;31m%s\033[0m"
	DebugColor  = "\033[0;36m%s\033[0m"
	OKColor     = "\033[0;32m%s\033[0m"
)

type Entity struct {
	wallet *SimpleWallet
	Name   string
}

func (e *Entity) GetWallet() *SimpleWallet {
	return e.wallet
}
func NewEntity(name string, keyType string) (*Entity, error) {
	e := Entity{
		wallet: NewSimpleWallet(),
		Name:   name,
	}
	err := e.wallet.Init(keyType)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func initSampleBody() (error, did.DID) {
	kt := crypto.Ed25519
	pubKey, _, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		return err, nil
	}
	did, err := did.PeerMethod0{}.Generate(kt, pubKey)
	if err != nil {
		return err, nil
	}
	return nil, did
}

func InitSampleDID() (error, did.DID) {
	return initSampleBody()
}

// Custom step writer pre-formats
// to stdout logs via steps, actions, and notes
type CustomStepWriter struct {
	step int
}

func (i *CustomStepWriter) Write(s string) {
	fmt.Printf(StepColor, fmt.Sprintf("Step %d: %s\n", i.step, s))
	i.step += 1
}

func (i *CustomStepWriter) WriteAction(s string) {
	fmt.Printf(ActionColor, fmt.Sprintf("  - %s\n", s))
}

func (i *CustomStepWriter) WriteError(s string) {
	fmt.Printf(ErrorColor, fmt.Sprintf("ERROR: %s\n", s))
}

func (i *CustomStepWriter) WriteOK(s string) {
	fmt.Printf(OKColor, fmt.Sprintf("OK: %s\n", s))
}

func (i *CustomStepWriter) WriteNote(s string) {
	fmt.Printf(NoteColor, fmt.Sprintf("      note: %s\n", s))
}

// This validates the VC.
// TODO: Expand on this more
// Simplify it?
func validateVC(vc credential.VerifiableCredential) error {

	issuer := "https://example.edu/issuers/565049"
	var AssertionMethod cryptosuite.ProofPurpose = "assertionMethod"
	var vc2 credential.VerifiableCredential
	err := util.Copy(&vc, &vc2)
	if err != nil {
		return err
	}
	var OKP = cryptosuite.KTY("OKP")
	var Ed25519 = cryptosuite.CRV("Ed25519")

	jwk, err := cryptosuite.GenerateJSONWebKey2020(OKP, Ed25519)
	if err != nil {
		return err
	}

	signer, err := cryptosuite.NewJSONWebKeySigner(issuer, jwk.PrivateKeyJWK, AssertionMethod)
	if err != nil {
		return err
	}
	suite := cryptosuite.GetJSONWebSignature2020Suite()
	err = suite.Sign(signer, &vc2)
	if err != nil {
		return err
	}
	verifier, err := cryptosuite.NewJSONWebKeyVerifier(issuer, jwk.PublicKeyJWK)
	if err != nil {
		return err
	}
	err = suite.Verify(verifier, &vc2)
	if err != nil {
		return err
	}
	return nil
}

// Build a presentation request (PR)
// A PR is sent by a holder to a verifier
// It can be sent over multiple mechanisms
// For more information, please go to here:
// https://identity.foundation/presentation-exchange/#presentation-request
// and for the source code with the sdk,
// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/exchange/request.go
// is appropriate to start off with.
func makePresentationRequest(jwk cryptosuite.JSONWebKey2020, presentationData exchange.PresentationDefinition, targetId string) (pr []byte, signer *cryptosuite.JSONWebKeySigner, err error) {

	cw.WriteNote("Presentation Request (JWT) is created")

	// Signer:
	// https://github.com/TBD54566975/ssi-sdk/blob/main/cryptosuite/jsonwebkey2020.go#L350
	// Implements: https://github.com/TBD54566975/ssi-sdk/blob/main/cryptosuite/jwt.go#L12
	signer, err = cryptosuite.NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, cryptosuite.Authentication)
	if err != nil {
		return
	}

	// Builds a presentation request
	// Requires a signeer, the presentation data, and the target
	// Target is the Audience Key
	requestJWTBytes, err := exchange.BuildJWTPresentationRequest(*signer, presentationData, targetId)
	if err != nil {
		return
	}

	return requestJWTBytes, signer, err
}

func MakePresentationRequest(jwk cryptosuite.JSONWebKey2020, presentationData exchange.PresentationDefinition, targetId string) (pr []byte, signer *cryptosuite.JSONWebKeySigner, err error) {
	return makePresentationRequest(jwk, presentationData, targetId)
}

// normalizePresentationClaims takes a set of Presentation Claims and turns them into map[string]interface{} as
// go-JSON representations. The claim format and signature algorithm type are noted as well.
// This method is greedy, meaning it returns the set of claims it was able to normalize.
func normalizePresentationClaims(claims []exchange.PresentationClaim) []exchange.NormalizedClaim {
	var normalizedClaims []exchange.NormalizedClaim
	for _, claim := range claims {
		ae := util.NewAppendError()
		claimJSON, err := claim.GetClaimJSON()
		if err != nil {
			ae.Append(err)
		}
		claimFormat, err := claim.GetClaimFormat()
		if err != nil {
			ae.Append(err)
		}
		if ae.Error() != nil {
			logrus.WithError(ae.Error()).Error("could not normalize claim")
			continue
		}
		var id string
		if claimID, ok := claimJSON["id"]; ok {
			id = claimID.(string)
		}
		normalizedClaims = append(normalizedClaims, exchange.NormalizedClaim{
			ID:             id,
			Data:           claimJSON,
			Format:         claimFormat,
			AlgOrProofType: claim.SignatureAlgorithmOrProofType,
		})
	}
	return normalizedClaims
}

func BuildPresentationSubmission(presentationRequest []byte, signer cryptosuite.Signer, verifier cryptosuite.JSONWebKeyVerifier, vc credential.VerifiableCredential) ([]byte, error) {
	return buildPresentationSubmission(presentationRequest, signer, verifier, vc)
}

// https://github.com/TBD54566975/ssi-sdk/blob/d279ca2779361091a70b8aa3c685a388067409a9/credential/exchange/submission.go#L126
//
func buildPresentationSubmission(presentationRequest []byte, signer cryptosuite.Signer, verifier cryptosuite.JSONWebKeyVerifier, vc credential.VerifiableCredential) ([]byte, error) {

	presentationClaim := exchange.PresentationClaim{
		Credential:                    &vc,
		LDPFormat:                     exchange.LDPVC.Ptr(),
		SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
	}

	parsed, err := verifier.VerifyAndParseJWT(string(presentationRequest))
	if err != nil {
		return nil, err
	}

	def, ok := parsed.Get(exchange.PresentationDefinitionKey)
	if !ok {
		return nil, fmt.Errorf("presentation definition key<%s> not found in token", exchange.PresentationDefinitionKey)
	}

	dat, err := json.Marshal(def)
	if err != nil {
		return nil, err
	}
	var pd exchange.PresentationDefinition
	err = json.Unmarshal(dat, &pd)
	if err != nil {
		return nil, err
	}

	submissionBytes, err := exchange.BuildPresentationSubmission(signer, pd, []exchange.PresentationClaim{presentationClaim}, exchange.JWTVPTarget)
	if err != nil {
		return nil, err
	}

	return submissionBytes, nil
}

func MakePresentationData(id string, inputID string) (exchange.PresentationDefinition, error) {
	return makePresentationData(id, inputID)
}

// Makes a dummy presentation definition. These are
// eventually transported via Presentation Request.
// For more information on presentation definitions go
// https://identity.foundation/presentation-exchange/#term:presentation-definition
func makePresentationData(id string, inputID string) (exchange.PresentationDefinition, error) {
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
	cw.WriteNote("Presentation Definition is formed. Asks for the issuer and the data from the issuer")
	err := def.IsValid()
	return def, err
}

func handleError(err error) {
	if err != nil {
		cw.WriteError(err.Error())
		os.Exit(1)
	}
}
