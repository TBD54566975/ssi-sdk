package main

import (
	gocrypto "crypto"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/google/uuid"
)

var cw = CustomStepWriter{}

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
	registry              = NewExampleRegistry()
)

// Implemented here is a very simple registry
// The data field maps the did to the did doc.
// In practice, registries can be much more
// complicated.
type ExampleRegistry struct {
	mux  *sync.Mutex
	data map[string]*did.DIDDocument
}

type ExampleDID string

// Defererence takes the existing DID key
// and converts it into a did document
func (e ExampleDID) Dereference() (*did.DIDDocument, error) {
	return &did.DIDDocument{}, nil
}

func NewExampleRegistry() *ExampleRegistry {
	return &ExampleRegistry{
		mux:  &sync.Mutex{},
		data: make(map[string]*did.DIDDocument),
	}
}

// Adds a DID Document to the registry
func (e *ExampleRegistry) Add(doc *did.DIDDocument) error {
	e.mux.Lock()
	defer e.mux.Unlock()
	if _, ok := e.data[doc.ID]; ok {
		return errors.New("ID already exists")
	}
	e.data[doc.ID] = doc
	return nil
}

// A DID Resolver resolves a DID Document via a DID string
// Different registries have different methodlogies for
// resolving the DID.
// The method specifies how to interact with the registry.
// For example:
// did:example:myid means that
// will specify that using the example method, resolve
// myid. Different methods will have different method specific
// identifiers and ways to resolve itself.
// See: https://w3c-ccg.github.io/did-resolution/ for more information.
func (e *ExampleRegistry) Resolve(s string) (*did.DIDDocument, error) {
	if d, ok := e.data[s]; !ok {
		return nil, errors.New("Could not resolve")
	} else {
		return d, nil
	}
}

// Creates a simple DID
func createExampleDID() *ExampleDID {
	key := ExampleDID(fmt.Sprintf("%s:%s", "example", uuid.New().String()))
	return &key
}

// Resolves a DID
// Right the current implementation ssk-sdk does
// not have a universal resolver.
// https://github.com/decentralized-identity/universal-resolver
// is a case where a universal resolver is implemented,
// but the resolution would need to be hooked with the sdk.
func resolveDID(didStr string) (*did.DIDDocument, error) {
	split := strings.Split(string(didStr), ":")
	if len(split) < 2 {
		return nil, errors.New("Invalid DID. Does not split correctly")
	}
	var method = split[1]
	switch method {
	case "key":
		return did.DIDKey(didStr).Expand()
	case "example":
		return ExampleDID(didStr).Dereference()
	default:
		return nil, fmt.Errorf("%v. Got %v method", UNSUPPORTED_DID_ERROR, method)
	}
}

// Make a verifiable credential DID Document
func makeVCDIDDocument(didKey string) did.DIDDocument {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement

	// Create the DID Document
	// This is just one of many ways to get the
	// DID Document from the Key.
	vcDoc := did.DIDDocument{
		Context: knownContext,
		ID:      didKey,
		Authentication: []did.VerificationMethodSet{
			[]string{didKey},
		},
	}
	return vcDoc
}

// Initalizes the University identity
// Gives it a DID Document, on the Example Registry
func initUniversity() *ExampleDID {
	// On the example network. Using the example method
	var vcDID = createExampleDID()
	vcDoc := makeVCDIDDocument(string(*vcDID))

	// register the DID
	registry.Add(&vcDoc)
	cw.WriteNote(fmt.Sprintf("Initialized University DID: %s and registered it", *vcDID))
	return vcDID
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

	// TODO: Proof?

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
		cw.WriteNote(fmt.Sprintf("Credentials made for: %s", string(dat)))
	}

	return &knownCred, nil
}

// A sample wallet
// This would NOT be how it would be stored in production
// But serves for demonstrative purposes
type SimpleWallet struct {
	vCs     map[string]*credential.VerifiableCredential
	privKey gocrypto.PrivateKey
	didKey  *did.DIDKey
	mux     *sync.Mutex
}

func NewSimpleWallet() *SimpleWallet {
	return &SimpleWallet{
		vCs: make(map[string]*credential.VerifiableCredential),
		mux: &sync.Mutex{},
	}
}

// Adds a Verifable Credential to a wallet
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
func (s *SimpleWallet) Init() error {
	s.mux.Lock()
	s.mux.Unlock()

	privKey, didKey, err := did.GenerateDIDKey(crypto.Secp256k1)
	if err != nil {
		panic("Failed to initialize user")
	}
	s.privKey = privKey
	s.didKey = didKey
	doc, err := didKey.Expand()
	if err != nil {
		return err
	}
	registry.Add(doc)
	cw.WriteNote(fmt.Sprintf("DID Key for user is: %s", *didKey))
	if dat, err := json.Marshal(doc); err == nil {
		cw.WriteNote(fmt.Sprintf("DID Document after expansion: %s", string(dat)))
	}

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
		return nil, err
	}

	_, err = verifier.VerifyAndParseJWT(string(requestJWTBytes))
	if err != nil {
		return nil, err
	}

	return requestJWTBytes, err
}

func validateAccess(data []byte) bool {
	return false
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

	// Wallet initialization
	cw.Write("Holder initiates a simple wallet")
	var wallet = NewSimpleWallet()
	cw.WriteAction("Wallet Created")
	cw.WriteAction("Wallet Initialized")
	if err := wallet.Init(); err != nil {
		panic(err)
	}

	// University Initializtion
	cw.Write("Initializing University Credentials")
	vcDID := initUniversity()
	cw.Write("Example University Creates VC for Holder")
	cw.WriteNote("DID is shared from holder")
	vc, err := buildExampleUniversityVC(string(*vcDID), string(*wallet.didKey))
	if err != nil {
		panic(err)
	} else {
		cw.WriteAction("VC Created")
	}

	// Verification
	cw.Write("Example University Sends VC to Holder")
	wallet.AddCredentials(vc)
	msg := fmt.Sprintf("VC puts into wallet. Wallet size is now: %d", wallet.Size())
	cw.WriteNote(msg)

	cw.Write("Employer wants to verify student graduated from Example University. Sends a presentation request")
	cw.WriteNote("Student shares proof via a Presentation Request")
	presentationData := makePresentationData()
	data, err := makePresentationRequest(presentationData)
	if err != nil {
		panic(err)
	}
	cw.WriteNote(fmt.Sprintf("Presentation Request:%s", string(data)))
	// Access
	accessGranted := validateAccess(data)
	cw.Write(fmt.Sprintf("Employer Grants Access: %v", accessGranted))
	if accessGranted == false {
		cw.WriteError("Access was not granted!")
	} else {
		cw.WriteOK("Access Granted!")
	}
}
