// Package ion provides all the functionality you need to interact with an ION service and manage your ION DID.
// To start, create a new ION resolver object using the NewResolver function. This will create a new resolver
// that can resolve and anchor ION DIDs. Next, create a new ION DID using the NewIONDID function. This will
// create a new ION DID object with a set of receiver methods that can be used to generate operations to submit
// to the ION service.
// For example:
// // Create a new ION resolver
// resolver, err := ion.NewResolver(http.DefaultClient, "https://ion.tbd.network")
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
// err = resolver.Anchor(ctx, createOp)
//
//	if err != nil {
//		panic(err)
//	}
//
// // Resolve the DID
// result, err := resolver.Resolve(ctx, did, nil)
//
//	if err != nil {
//		panic(err)
//	}
package ion

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

type (
	DIDION string
)

const (
	IONPrefix = "did:ion"
)

// IsValid checks if the did:ion is valid by checking for a valid prefix
// full validation is impossible without resolution
func (d DIDION) IsValid() bool {
	split := strings.Split(d.String(), IONPrefix+":")
	return len(split) == 2
}

func (d DIDION) String() string {
	return string(d)
}

func (d DIDION) Suffix() (string, error) {
	split := strings.Split(d.String(), IONPrefix+":")
	if len(split) != 2 {
		return "", errors.Wrap(util.InvalidFormatError, "did is malformed")
	}
	return split[1], nil
}

func (DIDION) Method() did.Method {
	return did.IONMethod
}

type Resolver struct {
	client  *http.Client
	baseURL url.URL
}

// NewIONResolver creates a new resolver for the ION DID method with a common base URL
// The base URL is the URL of the ION node, for example: https://ion.tbd.network
// The resolver will append the DID to the base URL to resolve the DID such as
//
//	https://ion.tbd.network/identifiers/did:ion:1234
//
// and similarly for submitting anchor operations to the ION node...
//
//	https://ion.tbd.network/operations
func NewIONResolver(client *http.Client, baseURL string) (*Resolver, error) {
	if client == nil {
		return nil, errors.New("client cannot be nil")
	}
	parsedURL, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "invalid resolver URL")
	}
	if parsedURL.Scheme != "https" {
		return nil, errors.New("invalid resolver URL scheme; must use https")
	}
	return &Resolver{
		client:  client,
		baseURL: *parsedURL,
	}, nil
}

// Resolve resolves a did:ion DID by appending the DID to the base URL with the identifiers path and making a GET request
func (i Resolver) Resolve(ctx context.Context, id string, _ did.ResolutionOption) (*did.ResolutionResult, error) {
	if i.baseURL.String() == "" {
		return nil, errors.New("resolver URL cannot be empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.Join([]string{i.baseURL.String(), "identifiers", id}, "/"), nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving, with URL: %s", i.baseURL.String())
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving, with response %+v", resp)
	}
	if !is2xxStatusCode(resp.StatusCode) {
		return nil, fmt.Errorf("could not resolve DID: %q", string(body))
	}
	resolutionResult, err := did.ParseDIDResolution(body)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving did:ion DID<%s>", id)
	}
	return resolutionResult, nil
}

// Anchor submits an anchor operation to the ION node by appending the operations path to the base URL
// and making a POST request
func (i Resolver) Anchor(ctx context.Context, op AnchorOperation) error {
	if i.baseURL.String() == "" {
		return errors.New("resolver URL cannot be empty")
	}
	jsonOpBytes, err := json.Marshal(op)
	if err != nil {
		return errors.Wrapf(err, "marshalling anchor operation %+v", op)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.Join([]string{i.baseURL.String(), "operations"}, "/"), bytes.NewReader(jsonOpBytes))
	if err != nil {
		return errors.Wrap(err, "creating request")
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "posting anchor operation %+v", op)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "could not resolve with response %+v", resp)
	}
	if !is2xxStatusCode(resp.StatusCode) {
		return fmt.Errorf("anchor operation failed: %s", string(body))
	}
	return nil
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
	updatePubKeyJWK, updatePrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(updatePrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting update key pair to JWK")
	}

	// generate recovery key pair
	_, recoveryPrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating recovery keypair")
	}
	recoveryPubKeyJWK, recoveryPrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(recoveryPrivateKey)
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
	nextUpdatePubKeyJWK, nextUpdatePrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(nextUpdatePrivateKey)
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
	nextRecoveryPubKeyJWK, nextRecoveryPrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(nextRecoveryPrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting next recovery key pair to JWK")
	}

	// generate next update key pair
	_, nextUpdatePrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating next update keypair")
	}
	nextUpdatePubKeyJWK, nextUpdatePrivKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(nextUpdatePrivateKey)
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
