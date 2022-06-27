package main

import (
	gocrypto "crypto"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
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
)

var registry = NewExampleRegistry()

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
func (e *ExampleDID) Dereference() (*did.DIDDocument, error) {
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
func (e *ExampleRegistry) Resolve(s string) *did.DIDDocument {
	return e.data[s]
}

// Creates a simple DID
func createExampleDID() *ExampleDID {
	key := ExampleDID(fmt.Sprintf("%s:%s", "example", uuid.New().String()))
	return &key
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
func buildExampleUniversityVC(didKey string) (*credential.VerifiableCredential, error) {

	// On the example network. Using the example method
	var vcDID = createExampleDID()
	// expand to did Document

	// registry.Add(vcDID)

	// Example just defines a unique id per id

	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := "https://example.edu/issuers/565049"
	knownIssuanceDate := time.Now().Format(time.RFC3339)
	knownSubject := map[string]interface{}{
		"id": vcDID, //did:<method-name>:<method-specific-id>
		"alumniOf": map[string]interface{}{ // claims are here
			"id": didKey,
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
}

// In the simple wallet
// Stores a DID for a particular user and
// adds it to the registry
func (s *SimpleWallet) Init() error {
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

func (i *CustomStepWriter) WriteNote(s string) {
	fmt.Printf(NoteColor, fmt.Sprintf("      note: %s\n", s))
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

	cw.Write("Holder initiates a simple wallet")
	var wallet = SimpleWallet{}
	cw.WriteAction("Wallet Created")
	cw.WriteAction("Wallet Initialized")
	if err := wallet.Init(); err != nil {
		panic(err)
	}

	cw.Write("Example University Creates VC for Holder")
	cw.WriteNote("DID is shared from holder")
	_, err := buildExampleUniversityVC(string(*wallet.didKey))
	if err != nil {
		panic(err)
	} else {
		cw.WriteAction("VC Created")
	}

	cw.Write("Example University Sends VC to Holder")

	msg := fmt.Sprintf("VC puts into wallet. Wallet size is now: %d", wallet.Size())
	cw.Write(msg)

	cw.Write("Employer wants to verify student graduated from Example University. Sends a presentation request")

	cw.Write("Student shares proof via a Presentation Request")

	cw.Write("Employer validates the VC and lets through")
}
