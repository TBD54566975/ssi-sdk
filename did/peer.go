//                    DID Peer
// ------------------------------------------------
// https://identity.foundation/peer-did-method-spec/
//
// Peer based, self signed DID method.
//
// The method can be used independent of any central source of truth, and is
// intended to be cheap, fast, scalable, and secure. It is suitable for most
// private relationships between people, organizations, and things. We expect
// that peer-to-peer relationships in every blockchain ecosystem can benefit by
// offloading pairwise and n-wise relationships to peer DIDs.
package did

import (
	gocrypto "crypto"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
	"github.com/pkg/errors"
)

type DIDPeer string

var availablePeerMethods = map[string]peerDIDMethod{
	"0": method0{},
	"1": method1{},
	"2": method2{},
}

// ANBF specified here:
// https://identity.foundation/peer-did-method-spec/#method-specific-identifier
const (
	PeerMethodPrefix                = "peer"
	DIDPrefix                       = "did"
	PeerTransform                   = "z"
	PeerEncNumBasis                 = Base58BTCMultiBase
	PeerDIDRegex                    = `^did:peer:(([01](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))|(2((\.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))+(\.(S)[0-9a-zA-Z=]*)?)))$`
	PeerKnownContext                = "https://w3id.org/did/v1"
	PeerDIDCommMessagingAbbr string = "dm"
	PeerDIDCommMessaging     string = "DIDCommMessaging"
)

// Peer Method Schema:
// did:<method-prefix><nuumalgo><transform><multicodec><numericbasis>
func buildPeerDID(method int, transform, multicodec, numericbasis string) DIDPeer {
	return DIDPeer(fmt.Sprintf("%s:%s:%d%s%s%s", DIDPrefix, PeerMethodPrefix,
		method, transform, multicodec, numericbasis))
}

// Checks if peer DID is valid
// https://identity.foundation/peer-did-method-spec/index.html#recognizing-and-handling-peer-dids
func isPeerDID(did string) bool {
	r, err := regexp.Compile(PeerDIDRegex)
	if err != nil {
		panic(err)
	}
	return r.MatchString(did)
}

// Checks if the Peer DID is correctly
// formatted
func (d DIDPeer) IsValid() bool {
	return isPeerDID(string(d))
}

func (d DIDPeer) ToString() string {
	return string(d)
}

func (d DIDPeer) Parse() (string, error) {
	s, err := ParseDID(d, DIDPrefix+":"+PeerMethodPrefix+":")
	if err != nil {
		return "", err
	}
	// Return without the method
	return s[2:], nil
}

type peerDIDMethod interface {
	Generate() (gocrypto.PrivateKey, *DIDPeer, error)
	Decode(d DIDPeer) (*DIDDocument, error)
}

// Method 0: inception key without doc
// https://identity.foundation/peer-did-method-spec/index.html#generation-method
// The DID doc offers no endpoint. This makes the DID functionally equivalent to
// a did:key value For example,
// did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH is equivalent to
// did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
type method0 struct {
	kt crypto.KeyType
}

func makeDIDPeerFromEncoded(method int, encoded string) DIDPeer {
	return DIDPeer(fmt.Sprintf("%s:%s:%d%s", DIDPrefix, PeerMethodPrefix, method, encoded))
}

type byValue struct {
	Key       string `json:"key"`
	Signature string `json:"sig"`
}

//https://identity.foundation/peer-did-method-spec/#backing-storage
type PeerDelta struct {
	Change string    `json:"change"` // <base64url encoding of a change fragment>,
	By     []byValue `json:"by"`     //  [ {"key": <id of key>, "sig": <signature value>} ... ],
	When   int64     `json:"when"`   //<ISO8601/RFC3339 UTC timestamp with at least second precision>
}

func (a DIDPeer) Delta(b DIDPeer) (PeerDelta, error) {
	return PeerDelta{}, errors.Wrap(util.NOT_IMPLEMENTED_ERROR, "peer:did delta")
}

// TODO: CRDT
// https://identity.foundation/peer-did-method-spec/#crdts

// decode public key with type
func decodePublicKeyWithType(data []byte) ([]byte, cryptosuite.LDKeyType, error) {

	encoding, decoded, err := multibase.Decode(string(data))
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to decode public key for did:peer")
	}

	if encoding != Base58BTCMultiBase {
		err := fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
		return nil, "", err
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", err
	}

	if n != 2 {
		errMsg := "error parsing did:peer varint"
		return nil, "", errors.New(errMsg)
	}

	pubKeyBytes := decoded[n:]
	multiCodecValue := multicodec.Code(multiCodec)
	switch multiCodecValue {
	case Ed25519MultiCodec:
		return pubKeyBytes, Ed25519VerificationKey2020, nil
	case X25519MultiCodec:
		return pubKeyBytes, X25519KeyAgreementKey2020, nil
	case Secp256k1MultiCodec:
		return pubKeyBytes, EcdsaSecp256k1VerificationKey2019, nil
	case P256MultiCodec, P384MultiCodec, P521MultiCodec, RSAMultiCodec:
		return pubKeyBytes, cryptosuite.JsonWebKey2020, nil
	default:
		err := fmt.Errorf("unknown multicodec for did:peer: %d", multiCodecValue)
		return nil, "", err
	}
}

// Generates the key by types
func (d DIDPeer) generateKeyByType(kt crypto.KeyType) (gocrypto.PublicKey, gocrypto.PrivateKey, error) {
	if !isSupportedKeyType(kt) {
		err := fmt.Errorf("%s : %s for did:peer", util.UNSUPPORTED_ERROR, kt)
		return nil, nil, err
	}
	return crypto.GenerateKeyByKeyType(kt)
}

// Method 0 Generation Method
func (m method0) Generate() (gocrypto.PrivateKey, *DIDPeer, error) {

	var did DIDPeer

	pubKey, privKey, err := did.generateKeyByType(m.kt)
	if err != nil {
		return nil, nil, err
	}

	encoded, err := encodePublicKeyWithKeyMultiCodecType(m.kt, pubKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not encode public key for did:peer")
	}

	did = makeDIDPeerFromEncoded(0, encoded)
	return privKey, &did, err
}

// Method 1: genesis doc
type method1 struct{}

// Method 2: multiple inception key without doc
type method2 struct {
	kt   crypto.KeyType
	keys []PeerMethod2Declaration
}

type PurposeType string

// https://identity.foundation/peer-did-method-spec/index.html#generation-method
const (
	PeerPurposeEncryptionCode           PurposeType = "E"
	PeerPurposeAssertionCode            PurposeType = "A"
	PeerPurposeVerificationCode         PurposeType = "V"
	PeerPurposeCapabilityInvocationCode PurposeType = "I"
	PeerPurposeCapabilityDelegationCode PurposeType = "D"
	PeerPurposeCapabilityServiceCode    PurposeType = "S"
)

var supportedDIDPeerPurposes = map[PurposeType]bool{
	PeerPurposeEncryptionCode:           true,
	PeerPurposeAssertionCode:            true,
	PeerPurposeVerificationCode:         true,
	PeerPurposeCapabilityDelegationCode: true,
	PeerPurposeCapabilityInvocationCode: true,
	PeerPurposeCapabilityServiceCode:    true,
}

type PeerMethod2Declaration struct {
	Purpose PurposeType
	Key     gocrypto.PublicKey
	Service Service
}

// You could hardcode this, which would reduce the # of puproses and
// possibly speed things up.
// But you'd also have to maintain it
// and lookups are harder for checking valid purposes
// we are going to build the list on the fly
func (d DIDPeer) getSupportedPurposes() []PurposeType {
	var i = 0
	var purposes = make([]PurposeType, len(supportedDIDPeerPurposes))
	for purpose, _ := range supportedDIDPeerPurposes {
		purposes[i] = purpose
		i += 1
	}
	return purposes
}

func (d DIDPeer) isValidPurpose(p PurposeType) bool {
	if _, ok := supportedDIDPeerPurposes[p]; ok {
		return true
	}
	return false
}

func (m method0) Decode(d DIDPeer) (*DIDDocument, error) {
	return nil, util.NOT_IMPLEMENTED_ERROR
}

func (m method1) Decode(d DIDPeer) (*DIDDocument, error) {
	return nil, util.NOT_IMPLEMENTED_ERROR

}

func (d DIDPeer) buildVerificationMethod(data, did string) (*VerificationMethod, error) {

	_, keyType, err := decodePublicKeyWithType([]byte(data))
	if err != nil {
		return nil, err
	}

	vm := VerificationMethod{
		ID:                 string(did) + "#" + data[1:],
		Type:               keyType,
		Controller:         string(did),
		PublicKeyMultibase: data,
	}

	return &vm, nil
}

// Split the DID string into element.
// Extract element purpose and decode each key or service.
// Insert each key or service into the document according to the designated pu
func (m method2) Decode(d DIDPeer) (*DIDDocument, error) {

	parsed, err := d.Parse()
	if err != nil {
		return nil, err
	}

	entries := strings.Split(parsed, ".")
	if len(entries) == 0 {
		return nil, errors.New("no entries found")
	}

	doc := NewDIDDocument()
	doc.ID = string(d)

	// How is this determined otherwise.
	// TODO: Don't hardcode this?
	doc.Context = PeerKnownContext

	for _, entry := range entries {

		serviceType := PurposeType(entry[0])

		switch serviceType {

		case PeerPurposeCapabilityServiceCode:

			service, err := d.decodeServiceBlock("." + entry)
			if err != nil {
				return nil, err
			}
			service.ID = string(d) + "#didcommmessaging-0"
			doc.Services = append(doc.Services, *service)

		case PeerPurposeEncryptionCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, errors.Wrap(err, "failed to build encryption code")
			}
			doc.KeyAgreement = append(doc.KeyAgreement, *vm)
		case PeerPurposeVerificationCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, errors.Wrap(err, "failed to build verification code")
			}
			doc.Authentication = append(doc.Authentication, *vm)
		case PeerPurposeCapabilityInvocationCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, errors.Wrap(err, "failed to build capabilities invocation code")
			}
			doc.CapabilityInvocation = append(doc.CapabilityInvocation, *vm)
		case PeerPurposeCapabilityDelegationCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, errors.Wrap(err, "failed to build capability delegation code")
			}
			doc.CapabilityDelegation = append(doc.CapabilityDelegation, *vm)
		default:
			return nil, errors.Wrap(util.UNSUPPORTED_ERROR, string(entry[0]))
		}
	}

	return doc, nil
}

// If numalgo == 2, the generation mode is similar to Method 0 (and therefore
// also did:key) with the ability to specify additional keys in the generated DID
// Document. This method is necessary when both an encryption key and a signing
// key are required.
//
//
// Start with the did prefix
// did:peer:2
// Construct a multibase encoded, multicodec-encoded form of each public key to be included.
// Prefix each encoded key with a period character (.) and single character from the purpose codes table below.
// Append the encoded key to the DID.
// Encode and append a service type to the end of the peer DID if desired as described below.
func (m method2) Generate() (gocrypto.PrivateKey, *DIDPeer, error) {

	var encoded string
	var did DIDPeer

	if len(m.keys) == 0 {
		return nil, nil, errors.New("no keys specified for did:peer. could not build.")
	}

	for i, k := range m.keys {

		var enc string
		var err error

		// Service must be appended last
		if k.Purpose == PeerPurposeCapabilityServiceCode && i < len(m.keys)-1 {
			return nil, nil, fmt.Errorf("failed to created did for %s. service must be appended last!", "did:peer")
		}

		if k.Purpose == PeerPurposeCapabilityServiceCode {
			enc, err = did.encodeService(k.Service)
			if err != nil {
				return nil, nil, errors.Wrap(err, "could not encode service for did:peer")
			}
		} else {
			enc, err = encodePublicKeyWithKeyMultiCodecType(m.kt, k.Key)
			if err != nil {
				return nil, nil, errors.Wrap(err, "could not encode public key for did:peer")
			}
		}
		encoded += "." + string(k.Purpose) + enc
	}

	did = makeDIDPeerFromEncoded(2, encoded)

	return nil, &did, nil
}

type PeerServiceBlockEncoded struct {
	ServiceType     string   `json:"t"`
	ServiceEndpoint string   `json:"s"`
	RoutingKeys     []string `json:"r"`
	Accept          []string `json:"a"`
}

// Start with the JSON structure for your service.
// Replace common strings in key names and type value with abbreviations from the abbreviations table below.
// Convert to string, and remove unnecessary whitespace, such as spaces and newlines.
// Base64URL Encode String (no padding)
// Prefix encoded service with a period character (.) and S
func (d DIDPeer) encodeService(p Service) (string, error) {

	if p.ServiceEndpoint == nil {
		return "", errors.Wrap(util.UNDEFINED_ERROR, "service endpoint is not defined")
	}

	var serviceBlock = PeerServiceBlockEncoded{
		ServiceType:     p.Type,
		ServiceEndpoint: p.ServiceEndpoint.(string),
		RoutingKeys:     p.RoutingKeys,
		Accept:          p.Accept,
	}

	if serviceBlock.ServiceType == PeerDIDCommMessaging {
		serviceBlock.ServiceType = PeerDIDCommMessagingAbbr
	}

	dat, err := json.Marshal(serviceBlock)
	if err != nil {
		return "", err
	}
	return b64.RawURLEncoding.EncodeToString([]byte(string(dat))), nil

}

// Checks if the service block is valid
func (d DIDPeer) checkValidPeerServiceBlock(s string) bool {
	if string(s[:2]) != "."+string(PeerPurposeCapabilityServiceCode) {
		return false
	}
	return true
}

// Decodes a service block
// Assumes that the service block has been stripped of
// any headers or identifiers.
func (d DIDPeer) decodeServiceBlock(s string) (*Service, error) {

	// check it starts with s.
	if !d.checkValidPeerServiceBlock(s) {
		return nil, errors.New("invalid string provided")
	}

	s2 := s[2:]

	decoded, err := b64.RawURLEncoding.DecodeString(s2)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode service for did:peer")
	}

	var psj PeerServiceBlockEncoded
	err = json.Unmarshal([]byte(decoded), &psj)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode JSON for peer service block")
	}
	var serviceBlock = Service{
		Type:            psj.ServiceType,
		ServiceEndpoint: psj.ServiceEndpoint,
		RoutingKeys:     psj.RoutingKeys,
		Accept:          psj.Accept,
	}

	if serviceBlock.Type == PeerDIDCommMessagingAbbr {
		serviceBlock.Type = PeerDIDCommMessaging
	}

	return &serviceBlock, nil
}

type ServiceTypeAbbreviationMap map[string]string

func (m method2) Encode() ([]byte, error) {
	return nil, util.NOT_IMPLEMENTED_ERROR

}

// https://identity.foundation/peer-did-method-spec/#generation-method Create a
// genesis version of JSON text of the DID doc for the DID. This inception key
// is the key that creates the DID and authenticates when exchanging it with the
// first peer CANNOT include the DID itself This lets the doc be created without
// knowing the DID's value in advance. Suppressing the DID value creates a
// stored variant of peer DID doc data, as opposed to the resolved variant that
// would have an actual DID value in the root id property. (In either the stored
// or resolved variant of the doc, anywhere else that the DID value would
// appear, it should appear as a relative reference rather than an absolute
// value. For example, eachcontroller property of a verificationMethod that is
// owned by this DID would say "controller": "#id".)

// Calculate the SHA256 [RFC4634] hash of the bytes of the stored variant of the
// genesis version of the DID doc, and make this value the new DID's numeric
// basis.
//
func (m method1) Generate() (gocrypto.PrivateKey, *DIDPeer, error) {
	// Create a Genesis Version
	return nil, nil, util.NOT_IMPLEMENTED_ERROR
}

// id:peer:<method>
func (d DIDPeer) GetMethod() (peerDIDMethod, error) {
	m := string(d[9])
	if v, ok := availablePeerMethods[m]; ok {
		return v, nil
	}
	return nil, errors.New(fmt.Sprintf("%s method not supported", m))
}

func (d DIDPeer) Resolve() (*DIDDocument, error) {

	m, err := d.GetMethod()
	if err != nil {
		return nil, err
	}

	return m.Decode(d)
}
