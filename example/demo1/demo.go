// A dead simple example of a full. Simulates that a student has graduated from a
// university. They are given a VC from the university and it is registered. An
// employer wants to ascertain if the student graduated from the university.
// They will request for the information, the student will respond.
//
// We use two different did methods here. did:key and a custom did method specified
// in this file: did:example. The university uses did:example and the
// user uses did:key.

// InitalizationStep: Initialize the Wallet/Holder and the University
// Step 0: Univesity issues a VC to the Holder and sends it over
// Step 1: Verifier requests data from the holder
// Step 2: Holder sends credential
// Step 3: Verifier grants access based on the result

//                          |--------------------------|
//                          |                          |
//                          |   Issuer (University)    |
//                          |                          |
//                          |__________________________|
//                             /                       \
//                            /                          \ Trusts University
//      -----------------    / Issues VC               -------------------------
//     |                |   /                         |                         |
//     |   Holder       |  / <--------------------->  |    Verifier (Employer)  |
//     |      \Wallet   |      PresentationRequest    |                         |
//     |----------------|                              --------------------------
//
//     In more complicated scenarios, a ledger is present which the verifier will interact with
//                              Ledge Based Scenario
//                              // TODO: Verify this
//
//                          |--------------------------|
//                          |                          |
//                          |   Issuer (University)    |
//                          |                          |
//                          |__________________________|
//                            |                       \
//                            |                          \ Trusts University
//      -----------------     | Issues VC to ledger   -------------------------
//     |                |     |                       |                         |
//     |   Holder       | <------------------------>  |    Verifier (Employer)  |
//     |      \Wallet   |     | PresentationRequest   |                         |
//     |----------------|     |                        --------------------------
//             | DID stored on|ledger                           | VC
//     |--------------------------------------------------------------------------|
//     |                               Ledger                                     |
//     ----------------------------------------------------------------------------

//  A couple nuances that are necessary to understand at a high level before
//  digging into this code.
//
//  1. A DID can be used against different method types. Each method has
//  different funtions. For example, bitcoin works differently than peer.
//  did:btcn vs. did:peer is how these methods specified.
//
//  2. A Verified Credential (VC) contains a cyrptographic proof, either explicit
//   or embedded into the VC. For the purposes of this demo, the proof is
//   embedded in a JSON Web Token (JTW)
//
//  3. When the Verifier wants to validate a user, they send a Presentation Request.
//   The response will contain the VC. The Verifier will be able to determine if the VC
//   has been tampered with due to the proof.
//
//   The objects being created are in the following order:
//
//  1. DID for the Holder
//  2. DID for the issuer
//  3. VC for the Holder from the verifier
//  4. PresentationRequest for the Verifier
//  5. PresentationSubmission from the Holder
//  6. Authorization from the Verifier.

package main

import (
	gocrypto "crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/sirupsen/logrus"
)

var cw = CustomStepWriter{}

// Set to debug mode here
var debug = os.Getenv("DEBUG")

func init() {
	if debug == "1" {
		println("Debug mode")
		logrus.SetLevel(logrus.DebugLevel)
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

var (
	UNSUPPORTED_DID_ERROR = errors.New("Unsupported Method for DID")
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
		return nil, errors.New("Invalid DID. Does not split correctly")
	}
	var method = split[1]
	switch method {
	case "key":
		return did.DIDKey(didStr).Expand()
	case "web":
		return did.DIDWeb(didStr).Resolve()
	case "peer":
		return did.DIDPeer(didStr).Resolve()
	default:
		return nil, fmt.Errorf("%v. Got %v method", UNSUPPORTED_DID_ERROR, method)
	}
}

type Entity struct {
	wallet *SimpleWallet
	Name   string
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

// Initalizes the University identity
// Gives it a DID Document, on the Example Registry
func initVerifier() (error, did.DID) {
	// On the example network. Using the example method
	return initSampleBody()
}

// Initalizes the University identity
// Gives it a DID Document, on the Example Registry
func initUniversity() (error, did.DID) {
	// On the example network. Using the example method
	return initSampleBody()
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

// Make a Verifiable Credential
// using the VC data type directly.
// Alternatively, use the builder
// A VC is set of tamper-evident claims and metadata
// that cryptographically prove who issued it
// Building a VC means using the CredentialBuilder
// as part of the credentials package in the ssk-sdk.
// VerifiableCredential is the verifiable credential model outlined in the
// vc-data-model spec https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#basic-concept
func buildExampleUniversityVC(universityID string, recipient string) (*credential.VerifiableCredential, error) {

	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := "https://example.edu/issuers/565049"
	knownIssuanceDate := time.Now().Format(time.RFC3339)
	knownSubject := map[string]interface{}{
		"id": universityID, //did:<method-name>:<method-specific-id>
		"alumniOf": map[string]interface{}{ // claims are here
			"id": recipient,
			"name": []interface{}{
				map[string]interface{}{"value": "Example University",
					"lang": "en",
				}, map[string]interface{}{
					"value": "Exemple d'Université",
					"lang":  "fr",
				},
			},
		},
	}

	// This is an embedded proof.
	// For more information
	// https://github.com/TBD54566975/ssi-sdk/blob/main/cryptosuite/jwssignaturesuite_test.go#L357
	// https://www.w3.org/TR/vc-data-model/#proofs-signatures

	// For more information on VC object, go to:
	// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/model.go
	knownCred := credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	err := knownCred.IsValid()
	if err != nil {
		return nil, err
	}

	if dat, err := json.Marshal(knownCred); err == nil {
		logrus.Debug(string(dat))
	}

	cw.WriteNote(fmt.Sprintf("VC issued from %s to %s", universityID, recipient))

	return &knownCred, nil
}

// A sample wallet
// This would NOT be how it would be stored in production
// But serves for demonstrative purposes
// This holds the assigned dids
// private keys
// and vCs
type SimpleWallet struct {
	vCs  map[string]*credential.VerifiableCredential
	keys map[string]gocrypto.PrivateKey
	dids map[string]string
	mux  *sync.Mutex
}

func NewSimpleWallet() *SimpleWallet {
	return &SimpleWallet{
		vCs:  make(map[string]*credential.VerifiableCredential),
		mux:  &sync.Mutex{},
		dids: make(map[string]string),
		keys: make(map[string]gocrypto.PrivateKey),
	}
}

// Adds a Private Key to a wallet
func (s *SimpleWallet) AddPrivateKey(k string, key gocrypto.PrivateKey) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.keys[k]; !ok {
		s.keys[k] = key
	} else {
		return errors.New("Already an entry")
	}
	return nil
}

func (s *SimpleWallet) AddDIDKey(k string, key string) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.dids[k]; !ok {
		s.dids[k] = key
	} else {
		return errors.New("Already an entry")
	}
	return nil
}

func (s *SimpleWallet) GetDID(k string) (string, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if v, ok := s.dids[k]; ok {
		return v, nil
	} else {
		return "", errors.New("Not found")
	}
	return "", nil
}

func (s *SimpleWallet) AddCredentials(cred *credential.VerifiableCredential) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.vCs[cred.ID]; !ok {
		s.vCs[cred.ID] = cred
	} else {
		return errors.New("Duplicate Credential. Could not add.")
	}
	return nil
}

// In the simple wallet
// Stores a DID for a particular user and
// adds it to the registry
func (s *SimpleWallet) Init(keyType string) error {

	s.mux.Lock() // TODO: remove the muxes?
	s.mux.Unlock()

	var privKey gocrypto.PrivateKey
	var pubKey gocrypto.PublicKey

	var didStr string
	var err error

	if keyType == "peer" {
		kt := crypto.Ed25519
		pubKey, privKey, err = crypto.GenerateKeyByKeyType(kt)
		if err != nil {
			return err
		}
		didk, err := did.PeerMethod0{}.Generate(kt, pubKey)
		if err != nil {
			return err
		}
		didStr = didk.ToString()
	} else {
		var didKey *did.DIDKey
		privKey, didKey, err = did.GenerateDIDKey(crypto.Secp256k1)
		if err != nil {
			return err
		}
		didStr = string(*didKey)
	}

	cw.WriteNote(fmt.Sprintf("DID for holder is: %s", didStr))
	s.AddPrivateKey("main", privKey)
	cw.WriteNote(fmt.Sprintf("Private Key stored with wallet"))
	s.AddDIDKey("main", string(didStr))
	cw.WriteNote(fmt.Sprintf("DID Key stored in wallet"))

	return nil
}

func (s *SimpleWallet) Size() int {
	return len(s.vCs)
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

// Build a presentation request (PR)
// A PR is sent by a verifier to a holder
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

// https://github.com/TBD54566975/ssi-sdk/blob/d279ca2779361091a70b8aa3c685a388067409a9/credential/exchange/submission.go#L126
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

	// normalized := normalizePresentationClaims([]exchange.PresentationClaim{presentationClaim})
	// submissionBytes, err := exchange.BuildPresentationSubmissionVP(pd, normalized)
	// if err != nil {
	// 	return nil, err
	// }

	submissionBytes, err := exchange.BuildPresentationSubmission(signer, pd, []exchange.PresentationClaim{presentationClaim}, exchange.JWTVPTarget)
	if err != nil {
		return nil, err
	}

	return submissionBytes, nil
}

// // Verification can be a number of things:
// 1. Signature is Valid
// 2. Timestamps are valid
// 3. Credntial is trusted
func validateAccess(data []byte) error {

	jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
	if err != nil {
		return err
	}
	verifier, err := cryptosuite.NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
	if err != nil {
		return err
	}

	// Verify the signature
	_, err = verifier.VerifyAndParseJWT(string(data))
	if err != nil {
		return err
	}

	var vp exchange.PresentationSubmission
	err = json.Unmarshal(data, &vp)
	if err != nil {
		return err
	}

	// TODO: Add check for VC Schema
	// TODO: Add check for Timestamps

	// Check various fields.
	return nil
}

func handleError(err error) {
	if err != nil {
		cw.WriteError(err.Error())
		os.Exit(1)
	}
}

// In this example, we will
// buile a simple example of a standard flow
// between a student, a university, and an employer
// 1. A student graduates from a university.
// The university issues a VC to the student, saying they graduated
// 2. The student will store it in a "wallet"
// 3. An employer sends a request to verify that the student graduated
// the university.
func main() {
	cw.Write("Starting University Flow")

	// Wallet initialization
	cw.Write("Initializing Student")
	student, err := NewEntity("Student", "key")
	handleError(err)

	cw.Write("Initializing Employer")
	employer, err := NewEntity("Employer", "peer")
	handleError(err)
	verifier_did, err := employer.wallet.GetDID("main")
	handleError(err)

	cw.Write("Initializing University")
	university, err := NewEntity("University", "peer")
	handleError(err)
	vcDID, err := university.wallet.GetDID("main")
	handleError(err)
	cw.WriteNote(fmt.Sprintf("Initialized Verifier DID: %s and registered it", vcDID))

	// Creates the VC
	cw.Write("Example University Creates VC for Holder")
	cw.WriteNote("DID is shared from holder")
	holderDID, err := student.wallet.GetDID("main")
	handleError(err)

	vc, err := buildExampleUniversityVC(vcDID, holderDID)
	handleError(err)

	// Send to user
	cw.Write("Example University Sends VC to Holder")
	student.wallet.AddCredentials(vc)
	msg := fmt.Sprintf("VC puts into wallet. Wallet size is now: %d", student.wallet.Size())
	cw.WriteNote(msg)

	cw.WriteNote(fmt.Sprintf("initialized verifier DID: %v", verifier_did))

	// 	Presentation Request
	cw.Write("Employer wants to verify student graduated from Example University. Sends a presentation request")
	presentationData, err := makePresentationData("test-id", "id-1")
	handleError(err)
	if dat, err := json.Marshal(presentationData); err == nil {
		logrus.Debugf("Presentation Data:\n%v", string(dat))
	}

	jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
	if err != nil {
		return
	}

	presentationRequest, _, err := makePresentationRequest(*jwk, presentationData, holderDID)
	handleError(err)

	verifier, err := cryptosuite.NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
	handleError(err)

	signer, err := cryptosuite.NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, cryptosuite.AssertionMethod)
	handleError(err)

	// 	send the PR back
	cw.WriteNote("Student returns claims via a Presentation Submission")
	submission, err := buildPresentationSubmission(presentationRequest, signer, *verifier, *vc)
	handleError(err)

	vp, err := signing.VerifyVerifiablePresentationJWT(*verifier, string(submission))
	handleError(err)

	if dat, err := json.Marshal(vp); err == nil {
		logrus.Debugf("Submission:\n%v", string(dat))
	}

	// Access
	err = validateAccess(submission)
	cw.Write(fmt.Sprintf("Employer Attempting to Grant Access"))
	if err != nil {
		cw.WriteError(fmt.Sprintf("Access was not granted! Reason: %s", err))
	} else {
		cw.WriteOK("Access Granted!")
	}
}
