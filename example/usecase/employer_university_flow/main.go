// A dead simple example of a full. Simulates that a student has graduated from a university. They are given a VC
// from the university. An employer wants to ascertain if the student graduated from the university. They will request
// the information, the student will respond.
//
// We use two different did methods here. did:key and a custom did method specified in this file: did:example.
// The university uses did:example and the user uses did:key.

// Initialization Step: Initialize the Wallet/Holder and the University
// Step 0: University issues a VC to the Holder and sends it over
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
//  A couple nuances that are necessary to understand at a high level before
//  digging into this code.
//
//  1. A DID can be used against different method types. Each method has
//  different functions. For example, bitcoin works differently than peer.
//  did:btc vs. did:peer is how these methods specified.
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
//  1. DIDs and wallets are created for the holder, issuer, and verifier
//  3. VC is issued to the student holder
//  4. PresentationRequest submitted by the verifier
//  5. PresentationSubmission returned by the holder
//  6. Authorization from the Verifier.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/goccy/go-json"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/did/peer"
	"github.com/TBD54566975/ssi-sdk/did/resolver"
	"github.com/TBD54566975/ssi-sdk/example"
	emp "github.com/TBD54566975/ssi-sdk/example/usecase/employer_university_flow/pkg"
)

// Set to debug mode here
var debug = os.Getenv("DEBUG")

const (
	DebugMode = "1"
)

// set mode for debugging
// in bash:
// export DEBUG=1
func init() {
	if debug == DebugMode {
		println("Debug mode")
		logrus.SetLevel(logrus.DebugLevel)
	}
}

// In this example, we will build a simple example of a standard flow between a student, a university, and an employer
// 1. A student graduates from a university. The university issues a VC to the student, saying they graduated
// 2. The student will store it in a "wallet"
// 3. An employer sends a request to verify that the student graduated from the university.
func main() {
	step := 0

	example.WriteStep("Starting University Flow", step)
	step++

	// Wallet initialization
	example.WriteStep("Initializing Student", step)
	step++

	student, err := emp.NewEntity("Student", did.KeyMethod)
	example.HandleExampleError(err, "failed to create student")
	studentDID := student.GetWallet().GetDIDs()[0]
	studentKeys, err := student.GetWallet().GetKeysForDID(studentDID)
	studentKey := studentKeys[0].Key
	studentKID := studentKeys[0].ID
	example.HandleExampleError(err, "failed to get student key")

	example.WriteStep("Initializing Employer", step)
	step++

	employer, err := emp.NewEntity("Employer", "peer")
	example.HandleExampleError(err, "failed to make employer identity")
	employerDID := employer.GetWallet().GetDIDs()[0]
	employerKeys, err := employer.GetWallet().GetKeysForDID(employerDID)
	employerKey := employerKeys[0].Key
	employerKID := employerKeys[0].ID
	example.HandleExampleError(err, "failed to get employer key")

	example.WriteStep("Initializing University", step)
	step++

	university, err := emp.NewEntity("University", did.PeerMethod)
	example.HandleExampleError(err, "failed to create university")
	universityDID := university.GetWallet().GetDIDs()[0]
	universityKeys, err := university.GetWallet().GetKeysForDID(universityDID)
	universityKey := universityKeys[0].Key
	universityKID := universityKeys[0].ID
	example.HandleExampleError(err, "failed to get university key")

	example.WriteNote(fmt.Sprintf("Initialized University (Verifier) DID: %s and registered it", universityDID))

	example.WriteStep("Example University Creates VC for Holder", step)
	step++

	universitySigner, err := jwx.NewJWXSigner(universityDID, universityKID, universityKey)
	example.HandleExampleError(err, "failed to build university signer")
	vcID, vc, err := emp.BuildExampleUniversityVC(*universitySigner, universityDID, studentDID)
	example.HandleExampleError(err, "failed to build vc")

	example.WriteStep("Example University Sends VC to Student (Holder)", step)
	step++

	err = student.GetWallet().AddCredentialJWT(vcID, vc)
	example.HandleExampleError(err, "failed to add credentials to wallet")

	msg := fmt.Sprintf("VC is stored in wallet. Wallet size is now: %d", student.GetWallet().Size())
	example.WriteNote(msg)

	example.WriteNote(fmt.Sprintf("initialized Employer (Verifier) DID: %v", employerDID))
	example.WriteStep("Employer wants to verify student graduated from Example University. Sends a presentation request", step)
	step++

	presentationData, err := emp.MakePresentationData("test-id", "id-1", universityDID)
	example.HandleExampleError(err, "failed to create pd")

	dat, err := json.Marshal(presentationData)
	example.HandleExampleError(err, "failed to marshal presentation data")
	logrus.Debugf("Presentation Data:\n%v", string(dat))

	presentationRequestJWT, employerSigner, err := emp.MakePresentationRequest(employerKey, employerKID, presentationData, employerDID, studentDID)
	example.HandleExampleError(err, "failed to make presentation request")

	studentSigner, err := jwx.NewJWXSigner(studentDID, studentKID, studentKey)
	example.HandleExampleError(err, "failed to build json web key signer")

	example.WriteNote("Student returns claims via a Presentation Submission")

	employerVerifier, err := employerSigner.ToVerifier(studentDID)
	example.HandleExampleError(err, "failed to build employer verifier")
	submission, err := emp.BuildPresentationSubmission(string(presentationRequestJWT), *employerVerifier, *studentSigner, vc)
	example.HandleExampleError(err, "failed to build presentation submission")

	verifier, err := studentSigner.ToVerifier(employerDID)
	example.HandleExampleError(err, "failed to construct verifier")

	resolver, err := resolver.NewResolver([]resolver.Resolver{key.KeyResolver{}, peer.PeerResolver{}}...)
	example.HandleExampleError(err, "failed to create DID resolver")
	_, _, vp, err := credential.VerifyVerifiablePresentationJWT(context.Background(), *verifier, resolver, string(submission))
	example.HandleExampleError(err, "failed to verify jwt")

	dat, err = json.Marshal(vp)
	example.HandleExampleError(err, "failed to marshal submission")
	logrus.Debugf("Submission:\n%v", string(dat))

	example.WriteStep(fmt.Sprintf("Employer Attempting to Grant Access"), step)
	if err = emp.ValidateAccess(*verifier, resolver, submission); err == nil {
		example.WriteOK("Access Granted!")
	} else {
		example.WriteError(fmt.Sprintf("Access was not granted! Reason: %s", err))
	}
}
