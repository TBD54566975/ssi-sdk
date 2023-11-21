// Package ion provides all the functionality you need to interact with an ION service and manage your ION DID.
// To start, create a new ION resolution object using the NewResolver function. This will create a new resolution
// that can resolve and anchor ION DIDs. Next, create a new ION DID using the NewIONDID function. This will
// create a new ION DID object with a set of receiver methods that can be used to generate operations to submit
// to the ION service.
// For example:
// // Create a new ION resolution
// resolution, err := ion.NewResolver(http.DefaultClient, "https://ion.tbd.network")
//
//	if err != nil {
//		panic(err)
//	}
//
// // Create a new ION DID
// did, createOp, err := ion.NewIONDID(Document{[]Service{Service{ID: "serviceID", Type: "serviceType"}}})
//
//	if err != nil {
//		panic(err)
//	}
//
// // Submit the create operation to the ION service
// err = resolution.Anchor(ctx, createOp)
//
//	if err != nil {
//		panic(err)
//	}
//
// // Resolve the DID
// result, err := resolution.Resolve(ctx, did, nil)
//
//	if err != nil {
//		panic(err)
//	}
package ion

import (
	"reflect"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

type (
	ION string
)

const (
	Prefix = "did:ion"
)

// IsValid checks if the did:ion is valid by checking for a valid prefix
// full validation is impossible without resolution
func (d ION) IsValid() bool {
	split := strings.Split(d.String(), Prefix+":")
	return len(split) == 2
}

func (d ION) String() string {
	return string(d)
}

func (d ION) Suffix() (string, error) {
	split := strings.Split(d.String(), Prefix+":")
	if len(split) != 2 {
		return "", errors.Wrap(util.InvalidFormatError, "did is malformed")
	}
	return split[1], nil
}

func (ION) Method() did.Method {
	return did.IONMethod
}

// DID is a representation of a did:ion DID and should be used to maintain the state of an ION
// DID Document. It contains the DID suffix, the long form DID, the operations of the DID, and both
// the update and recovery private keys. All receiver methods are side effect free, and return new
// instances of DID with the updated state.
type DID struct {
	id                 string
	suffix             string
	longFormDID        string
	operations         []any
	updatePrivateKey   jwx.PrivateKeyJWK
	recoveryPrivateKey jwx.PrivateKeyJWK
}

func (d DID) IsEmpty() bool {
	return reflect.DeepEqual(d, DID{})
}

func (d DID) ID() string {
	return d.id
}

func (d DID) LongForm() string {
	return d.longFormDID
}

func (d DID) Operations() []any {
	return d.operations
}

func (d DID) Operation(index int) any {
	return d.operations[index]
}

func (d DID) GetUpdatePrivateKey() jwx.PrivateKeyJWK {
	return d.updatePrivateKey
}

func (d DID) GetRecoveryPrivateKey() jwx.PrivateKeyJWK {
	return d.recoveryPrivateKey
}

// NewIONDID creates a new ION DID with a new recovery and update key pairs, of type secp256k1, in addition
// to any content passed into in the document parameter. The result is a DID object that contains the long form DID,
// and operations to be submitted to an anchor service.
func NewIONDID(doc Document) (*DID, *CreateRequest, error) {
	if doc.IsEmpty() {
		return nil, nil, errors.New("document cannot be empty")
	}

	// generate update key pair
	_, updatePrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating update keypair")
	}
	updatePubKeyJWK, updatePrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(nil, updatePrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting update key pair to JWK")
	}

	// generate recovery key pair
	_, recoveryPrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating recovery keypair")
	}
	recoveryPubKeyJWK, recoveryPrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(nil, recoveryPrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting recovery keypair to JWK")
	}

	createRequest, err := NewCreateRequest(*recoveryPubKeyJWK, *updatePubKeyJWK, doc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating create request")
	}

	longFormDID, err := CreateLongFormDID(*recoveryPubKeyJWK, *updatePubKeyJWK, doc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating long form DID")
	}
	shortFormDID, err := LongToShortFormDID(longFormDID)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating short form DID")
	}
	suffix := shortFormDID[len("did:ion:"):]

	return &DID{
		id:                 shortFormDID,
		suffix:             suffix,
		longFormDID:        longFormDID,
		operations:         []any{createRequest},
		updatePrivateKey:   *updatePrivKeyJWK,
		recoveryPrivateKey: *recoveryPrivKeyJWK,
	}, createRequest, nil
}

// Update updates the DID object's state with a provided state change object. The result is a new DID object
// with the update key pair and an update operation to be submitted to an anchor service.
func (d DID) Update(stateChange StateChange) (*DID, *UpdateRequest, error) {
	if d.IsEmpty() {
		return nil, nil, errors.New("DID cannot be empty")
	}

	if err := stateChange.IsValid(); err != nil {
		return nil, nil, errors.Wrap(err, "invalid state change")
	}

	// generate next update key pair
	_, nextUpdatePrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating next update keypair")
	}
	nextUpdatePubKeyJWK, nextUpdatePrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(nil, nextUpdatePrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting next update key pair to JWK")
	}

	// create a signer with the current update key
	signer, err := NewBTCSignerVerifier(d.updatePrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating signer")
	}

	updateRequest, err := NewUpdateRequest(d.suffix, d.updatePrivateKey.ToPublicKeyJWK(), *nextUpdatePubKeyJWK, *signer, stateChange)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating update request")
	}

	updatedDID := DID{
		id:                 d.id,
		suffix:             d.suffix,
		longFormDID:        d.longFormDID,
		operations:         append(d.operations, updateRequest),
		updatePrivateKey:   *nextUpdatePrivKeyJWK,
		recoveryPrivateKey: d.recoveryPrivateKey,
	}
	return &updatedDID, updateRequest, nil
}

// Recover recovers the DID object's state with a provided document object, returning a new DID object and
// recover operation to be submitted to an anchor service.
func (d DID) Recover(doc Document) (*DID, *RecoverRequest, error) {
	if d.IsEmpty() {
		return nil, nil, errors.New("DID cannot be empty")
	}

	if doc.IsEmpty() {
		return nil, nil, errors.New("document cannot be empty")
	}

	// generate next recovery key pair
	_, nextRecoveryPrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating nest recovery keypair")
	}
	nextRecoveryPubKeyJWK, nextRecoveryPrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(nil, nextRecoveryPrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting next recovery key pair to JWK")
	}

	// generate next update key pair
	_, nextUpdatePrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating next update keypair")
	}
	nextUpdatePubKeyJWK, nextUpdatePrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(nil, nextUpdatePrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting next update key pair to JWK")
	}

	// create a signer with the current update key
	signer, err := NewBTCSignerVerifier(d.updatePrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating signer")
	}

	recoverRequest, err := NewRecoverRequest(d.suffix, d.recoveryPrivateKey.ToPublicKeyJWK(), *nextRecoveryPubKeyJWK, *nextUpdatePubKeyJWK, doc, *signer)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating recover request")
	}

	recoveredDID := DID{
		id:                 d.id,
		suffix:             d.suffix,
		longFormDID:        d.longFormDID,
		operations:         append(d.operations, recoverRequest),
		updatePrivateKey:   *nextUpdatePrivKeyJWK,
		recoveryPrivateKey: *nextRecoveryPrivKeyJWK,
	}
	return &recoveredDID, recoverRequest, nil
}

// Deactivate creates a terminal state DID and the corresponding anchor operation to submit to the anchor service.
func (d DID) Deactivate() (*DID, *DeactivateRequest, error) {
	if d.IsEmpty() {
		return nil, nil, errors.New("DID cannot be empty")
	}

	// create a signer with the current update key
	signer, err := NewBTCSignerVerifier(d.updatePrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating signer")
	}

	deactivateRequest, err := NewDeactivateRequest(d.suffix, d.updatePrivateKey.ToPublicKeyJWK(), *signer)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating deactivate request")
	}

	deactivatedDID := DID{
		id:                 d.id,
		suffix:             d.suffix,
		longFormDID:        d.longFormDID,
		operations:         append(d.operations, deactivateRequest),
		updatePrivateKey:   d.updatePrivateKey,
		recoveryPrivateKey: d.recoveryPrivateKey,
	}

	return &deactivatedDID, deactivateRequest, nil
}

func is2xxStatusCode(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}
