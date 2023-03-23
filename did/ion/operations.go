package ion

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
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
	baseURL string
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
func NewIONResolver(baseURL string) (*Resolver, error) {
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return nil, errors.Wrap(err, "invalid resolver URL")
	}
	return &Resolver{baseURL: baseURL}, nil
}

// Resolve resolves a did:ion DID by appending the DID to the base URL with the identifiers path and making a GET request
func (i Resolver) Resolve(id string, _ did.ResolutionOptions) (*did.DIDResolutionResult, error) {
	if i.baseURL == "" {
		return nil, errors.New("resolver URL is empty")
	}
	resp, err := http.Get(strings.Join([]string{i.baseURL, "identifiers", id}, "/"))
	if err != nil {
		return nil, errors.Wrapf(err, "could not resolve with docURL %+v", i.baseURL)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "could not resolve with response %+v", resp)
	}
	resolutionResult, err := did.ParseDIDResolution(body)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving did:ion DID: %s", id)
	}
	return resolutionResult, nil
}

// Anchor submits an anchor operation to the ION node by appending the operations path to the base URL
// and making a POST request
func (i Resolver) Anchor(op AnchorOperation) error {
	if i.baseURL == "" {
		return errors.New("resolver URL is empty")
	}
	jsonOpBytes, err := json.Marshal(op)
	if err != nil {
		return errors.Wrapf(err, "marshaling anchor operation %+v", op)
	}
	_, err = http.Post(strings.Join([]string{i.baseURL, "operations"}, "/"), "application/json", bytes.NewReader(jsonOpBytes))
	if err != nil {
		return errors.Wrapf(err, "posting anchor operation %+v", op)
	}
	return nil
}

type DID struct {
	id                 string
	suffix             string
	longFormDID        string
	operations         []any
	updatePrivateKey   crypto.PrivateKeyJWK
	recoveryPrivateKey crypto.PrivateKeyJWK
}

func (d *DID) ID() string {
	return d.id
}

func (d *DID) LongFormDID() string {
	return d.longFormDID
}

func (d *DID) Operations() []any {
	return d.operations
}

func (d *DID) Operation(index int) any {
	return d.operations[index]
}

// NewIONDID creates a new ION DID with a new recovery and update key pair  in addition to any content
// passed into in the document parameter. The document parameter is optional and can be nil. The result
// is a DID object that contains the long form DID, and operations to be submitted to an anchor service.
func NewIONDID(doc Document) (*DID, error) {
	// generate update key pair
	_, updatePrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, errors.Wrap(err, "generating update keypair")
	}
	updatePubKeyJWK, updatePrivKeyJWK, err := crypto.PrivateKeyToPrivateKeyJWK(updatePrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "converting update key pair to JWK")
	}

	// generate recovery key pair
	_, recoveryPrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, errors.Wrap(err, "generating recovery keypair")
	}
	recoveryPubKeyJWK, recoveryPrivKeyJWK, err := crypto.PrivateKeyToPrivateKeyJWK(recoveryPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "converting recovery keypair to JWK")
	}

	createRequest, err := NewCreateRequest(*recoveryPubKeyJWK, *updatePubKeyJWK, doc)
	if err != nil {
		return nil, errors.Wrap(err, "generating create request")
	}

	longFormDID, err := CreateLongFormDID(*recoveryPubKeyJWK, *updatePubKeyJWK, doc)
	if err != nil {
		return nil, errors.Wrap(err, "generating long form DID")
	}
	shortFormDID, err := GetShortFormDIDFromLongFormDID(longFormDID)
	if err != nil {
		return nil, errors.Wrap(err, "generating short form DID")
	}
	suffix := strings.Split(shortFormDID, ":")[2]

	return &DID{
		id:                 shortFormDID,
		suffix:             suffix,
		longFormDID:        longFormDID,
		operations:         []any{createRequest},
		updatePrivateKey:   *updatePrivKeyJWK,
		recoveryPrivateKey: *recoveryPrivKeyJWK,
	}, nil
}

// Update updates the DID object's state with a provided state change object. The result is a new
// update key pair and an update operation to be submitted to an anchor service.
func (d *DID) Update(stateChange StateChange) (*UpdateRequest, error) {
	// generate next update key pair
	_, nextUpdatePrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, errors.Wrap(err, "generating next update keypair")
	}
	nextUpdatePubKeyJWK, nextUpdatePrivKeyJWK, err := crypto.PrivateKeyToPrivateKeyJWK(nextUpdatePrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "converting next update key pair to JWK")
	}

	// create a signer with the current update key
	signer, err := NewBTCSignerVerifier(d.updatePrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "creating signer")
	}

	updateRequest, err := NewUpdateRequest(d.suffix, d.updatePrivateKey.ToPublicKeyJWK(), *nextUpdatePubKeyJWK, *signer, stateChange)
	if err != nil {
		return nil, errors.Wrap(err, "generating update request")
	}

	// update the DID object with the new update key
	d.updatePrivateKey = *nextUpdatePrivKeyJWK

	return updateRequest, nil
}

func (d *DID) Recover(doc Document) (*RecoverRequest, error) {
	// generate next recovery key pair
	_, nextRecoveryPrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, errors.Wrap(err, "generating nest recovery keypair")
	}
	nextRecoveryPubKeyJWK, nextRecoveryPrivKeyJWK, err := crypto.PrivateKeyToPrivateKeyJWK(nextRecoveryPrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "converting next recovery key pair to JWK")
	}

	// generate next update key pair
	_, nextUpdatePrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, errors.Wrap(err, "generating next update keypair")
	}
	nextUpdatePubKeyJWK, nextUpdatePrivKeyJWK, err := crypto.PrivateKeyToPrivateKeyJWK(nextUpdatePrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "converting next update key pair to JWK")
	}

	// create a signer with the current update key
	signer, err := NewBTCSignerVerifier(d.updatePrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "creating signer")
	}

	recoverRequest, err := NewRecoverRequest(d.suffix, d.recoveryPrivateKey.ToPublicKeyJWK(), *nextRecoveryPubKeyJWK, *nextUpdatePubKeyJWK, doc, *signer)
	if err != nil {
		return nil, errors.Wrap(err, "generating recover request")
	}

	// update the DID object with the new recovery and update keys
	d.recoveryPrivateKey = *nextRecoveryPrivKeyJWK
	d.updatePrivateKey = *nextUpdatePrivKeyJWK

	return recoverRequest, nil
}

func (d *DID) Deactivate() {

}
