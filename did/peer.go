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
//
// Currently only methods 0 and 2 are supported.
// Method 1 will be supported in a future date
package did

import (
	gocrypto "crypto"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type (
	DIDPeer     string
	PurposeType string
)

var availablePeerMethods = map[string]DIDResolver{
	"0": PeerMethod0{},
	"1": PeerMethod1{},
	"2": PeerMethod2{},
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
	Hash                            = "#"
)

// Checks if peer DID is valid
// https://identity.foundation/peer-did-method-spec/index.html#recognizing-and-handling-peer-dids
func isPeerDID(did string) bool {
	r, err := regexp.Compile(PeerDIDRegex)
	if err != nil {
		logrus.WithError(err).Error() // this should never happen
		return false
	}
	return r.MatchString(did)
}

// Checks if the Peer DID is correctly
// formatted
func (d DIDPeer) IsValid() bool {
	return isPeerDID(string(d))
}

func (d DIDPeer) Parse() (string, error) {

	s, err := ParseDID(d, strings.Join([]string{DIDPrefix, PeerMethodPrefix}, ":")+":")
	if err != nil {
		return "", err
	}

	method, err := d.GetMethodID()
	if err != nil {
		return "", err
	}

	var index int
	switch method {
	case "0":
		index = 1
	case "1":
		return "", errors.Wrap(util.NotImplementedError, "parsing method 1")
	case "2":
		index = 2
	}
	return s[index:], nil
}

// Method 0: inception key without doc
// https://identity.foundation/peer-did-method-spec/index.html#generation-method
// The DID doc offers no endpoint. This makes the DID functionally equivalent to
// a did:key value For example,
// did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH is equivalent to
// did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
type PeerMethod0 struct {
	kt crypto.KeyType
}

func buildDIDPeerFromEncoded(method int, encoded string) DIDPeer {
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

func (d DIDPeer) Delta(b DIDPeer) (*PeerDelta, error) {
	return nil, errors.Wrap(util.NotImplementedError, "peer:did delta")
}

// TODO: CRDT
// https://identity.foundation/peer-did-method-spec/#crdts

// Generates the key by types
func (d DIDPeer) generateKeyByType(kt crypto.KeyType) (gocrypto.PublicKey, gocrypto.PrivateKey, error) {
	if !isSupportedKeyType(kt) {
		err := fmt.Errorf("%s : %s for did:peer", util.UnsupportedError, kt)
		return nil, nil, err
	}
	return crypto.GenerateKeyByKeyType(kt)
}

func (m PeerMethod0) Generate(kt crypto.KeyType, publicKey gocrypto.PublicKey) (*DIDPeer, error) {
	var did DIDPeer
	encoded, err := encodePublicKeyWithKeyMultiCodecType(kt, publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not encode public key for did:peer")
	}
	did = buildDIDPeerFromEncoded(0, encoded)
	return &did, err
}

// Method 1: genesis doc
type PeerMethod1 struct{}

// Method 2: multiple inception key without doc
type PeerMethod2 struct {
	KT     crypto.KeyType
	Values []interface{}
}

// https://identity.foundation/peer-did-method-spec/index.html#generation-method
const (
	PeerPurposeEncryptionCode           PurposeType = "E"
	PeerPurposeAssertionCode            PurposeType = "A"
	PeerPurposeVerificationCode         PurposeType = "V"
	PeerPurposeCapabilityInvocationCode PurposeType = "I"
	PeerPurposeCapabilityDelegationCode PurposeType = "D"
	PeerPurposeCapabilityServiceCode    PurposeType = "S"
)

// For a quick lookup of supported DID purposes
var supportedDIDPeerPurposes = map[PurposeType]bool{
	PeerPurposeEncryptionCode:           true,
	PeerPurposeAssertionCode:            true,
	PeerPurposeVerificationCode:         true,
	PeerPurposeCapabilityDelegationCode: true,
	PeerPurposeCapabilityInvocationCode: true,
	PeerPurposeCapabilityServiceCode:    true,
}

func (d DIDPeer) IsValidPurpose(p PurposeType) bool {
	if _, ok := supportedDIDPeerPurposes[p]; ok {
		return true
	}
	return false
}

// Resolves a did:peer into a DID Document
// To do so, it decodes the key, constructs a verification
// method, and returns a DID Document
//
// This allows PeerMethod0 to implement the DID Resolver
// interface and be used to expand the did into the DID Document.
func (m PeerMethod0) Resolve(did DID, opts ResolutionOptions) (*DIDDocument, *DIDResolutionMetadata, *DIDDocumentMetadata, error) {

	d, ok := did.(DIDPeer)
	if !ok {
		return nil, nil, nil, errors.Wrap(util.CastingError, "did:peer")
	}

	v, err := d.Parse()
	if err != nil {
		return nil, nil, nil, err
	}

	pubKey, keyType, err := decodeEncodedKey(v)
	if err != nil {
		return nil, nil, nil, err
	}

	keyReference := Hash + v
	id := string(d)

	verificationMethod, err := constructVerificationMethod(id, keyReference, pubKey, keyType)
	if err != nil {
		return nil, nil, nil, err
	}

	verificationMethodSet := []VerificationMethodSet{
		[]string{keyReference},
	}

	return &DIDDocument{
		Context:              KnownDIDContext,
		ID:                   id,
		VerificationMethod:   []VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		KeyAgreement:         verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
	}, nil, nil, nil
}

func (m PeerMethod1) Resolve(d DID, opts ResolutionOptions) (*DIDDocument, *DIDResolutionMetadata, *DIDDocumentMetadata, error) {
	d, ok := d.(DIDPeer)
	if !ok {
		return nil, nil, nil, errors.Wrap(util.CastingError, "did:peer")
	}

	return nil, nil, nil, util.NotImplementedError

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
func (m PeerMethod2) Resolve(did DID, opts ResolutionOptions) (*DIDDocument, *DIDResolutionMetadata, *DIDDocumentMetadata, error) {

	d, ok := did.(DIDPeer)

	if !ok {
		return nil, nil, nil, errors.Wrap(util.CastingError, "did:peer")
	}

	parsed, err := d.Parse()
	if err != nil {
		return nil, nil, nil, err
	}

	entries := strings.Split(parsed, ".")
	if len(entries) == 0 {
		return nil, nil, nil, errors.New("no entries found")
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
				return nil, nil, nil, err
			}
			service.ID = string(d) + "#didcommmessaging-0"
			doc.Services = append(doc.Services, *service)
		case PeerPurposeEncryptionCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "failed to build encryption code")
			}
			doc.KeyAgreement = append(doc.KeyAgreement, *vm)
		case PeerPurposeVerificationCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "failed to build verification code")
			}
			doc.Authentication = append(doc.Authentication, *vm)
		case PeerPurposeCapabilityInvocationCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "failed to build capabilities invocation code")
			}
			doc.CapabilityInvocation = append(doc.CapabilityInvocation, *vm)
		case PeerPurposeCapabilityDelegationCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "failed to build capability delegation code")
			}
			doc.CapabilityDelegation = append(doc.CapabilityDelegation, *vm)
		default:
			return nil, nil, nil, errors.Wrap(util.UnsupportedError, string(entry[0]))
		}
	}
	return doc, nil, nil, nil
}

// If numalgo == 2, the generation mode is similar to Method 0 (and therefore
// also did:key) with the ability to specify additional keys in the generated DID
// Document. This method is necessary when both an encryption key and a signing
// key are required.
//
// It determines the purpose implicitly by looking at the type of object
//
// Start with the did prefix
// did:peer:2
// Construct a multibase encoded, multicodec-encoded form of each public key to be included.
// Prefix each encoded key with a period character (.) and single character from the purpose codes table below.
// Append the encoded key to the DID.
// Encode and append a service type to the end of the peer DID if desired as described below.
func (m PeerMethod2) Generate() (*DIDPeer, error) {

	var did DIDPeer

	if len(m.Values) == 0 {
		return nil, errors.New("no keys specified for did:peer. could not build.")
	}

	var encoded string
	var err error

	for i, value := range m.Values {

		var enc string
		var purpose PurposeType

		switch tt := value.(type) {
		case Service:
			purpose = PeerPurposeCapabilityServiceCode
			service := value.(Service)

			if i < len(m.Values)-1 {
				return nil, fmt.Errorf("failed to created did for %s. service must be appended last!", "did:peer")
			}

			if !service.IsValid() {
				return nil, errors.New("service purpose provided but invalid service definition given")
			}

			enc, err = did.encodeService(service)

			if err != nil {
				return nil, errors.Wrap(err, "could not encode service for did:peer")
			}

		case gocrypto.PublicKey:

			purpose = PeerPurposeEncryptionCode
			key := value.(gocrypto.PublicKey)
			enc, err = encodePublicKeyWithKeyMultiCodecType(m.KT, key)
			if err != nil {
				return nil, errors.Wrap(err, "could not encode public key for did:peer")
			}

		default:
			return nil, errors.Wrap(util.NotImplementedError, fmt.Sprintf("encoding of %s did:peer", tt))
		}

		encoded += "." + string(purpose) + enc
	}

	did = buildDIDPeerFromEncoded(2, encoded)

	return &did, nil
}

// Remaps the servce block for encoding
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
		return "", errors.Wrap(util.UndefinedError, "service endpoint is not defined")
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
func (m PeerMethod1) Generate() (*DIDPeer, error) {
	// Create a Genesis Version
	return nil, util.NotImplementedError
}

func (d DIDPeer) GetMethodID() (string, error) {
	m := string(d[9])
	if _, ok := availablePeerMethods[m]; ok {
		return m, nil
	}
	return "", errors.New(fmt.Sprintf("%s method not supported", m))
}

// id:peer:<method>
func (d DIDPeer) GetMethod() (DIDResolver, error) {

	m := string(d[9])

	if _, ok := availablePeerMethods[m]; ok {
		switch m {
		case "0":
			return PeerMethod0{}, nil
		case "1":
			return PeerMethod1{}, nil
		case "2":
			return PeerMethod2{}, nil
		default:
			return nil, errors.New(fmt.Sprintf("%s method not supported", m))
		}
	}

	return nil, errors.New(fmt.Sprintf("%s method not supported", m))
}

func (d DIDPeer) Resolve() (*DIDDocument, *DIDResolutionMetadata, *DIDDocumentMetadata, error) {
	m, err := d.GetMethod()
	if err != nil {
		return nil, nil, nil, err
	}
	did, rm, dm, err := m.Resolve(d, nil)
	return did, rm, dm, err
}

func (d DIDPeer) ToString() string {
	return string(d)
}
