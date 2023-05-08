// Package peer DID Peer
// ------------------------------------------------
// https://identity.foundation/peer-did-method-spec/
//
// Peer based, self-signed DID method.
//
// The method can be used independent of any central source of truth, and is intended to be cheap, fast, scalable,
// and secure. It is suitable for most private relationships between people, organizations, and things. We expect
// that peer-to-peer relationships in every blockchain ecosystem can benefit by offloading pairwise and n-wise
// relationships to peer DIDs.
//
// Currently only methods 0 and 2 are supported. Method 1 will be supported in a future date.
package peer

import (
	gocrypto "crypto"
	b64 "encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-json"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolver"
	"github.com/TBD54566975/ssi-sdk/util"
)

type (
	DIDPeer     string
	PurposeType string
)

// ANBF specified here:
// https://identity.foundation/peer-did-method-spec/#method-specific-identifier
const (
	DIDPeerPrefix                   = "did:peer"
	PeerEncNumBasis                 = did.Base58BTCMultiBase
	PeerDIDRegex                    = `^did:peer:(([01](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))|(2((\.[AEVID](z)([1-9a-km-zA-HJ-NP-Z]{46,47}))+(\.(S)[0-9a-zA-Z=]*)?)))$`
	PeerKnownContext                = "https://w3id.org/did/v1"
	PeerDIDCommMessagingAbbr string = "dm"
	PeerDIDCommMessaging     string = "DIDCommMessaging"
	Hash                            = "#"
)

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

// Checks if peer DID is valid
// https://identity.foundation/peer-did-method-spec/index.html#recognizing-and-handling-peer-dids
func isPeerDID(did string) bool {
	r, err := regexp.Compile(PeerDIDRegex)
	if err != nil {
		return false
	}
	return r.MatchString(did)
}

// IsValid Checks if the Peer DID is correctly formatted
func (d DIDPeer) IsValid() bool {
	return isPeerDID(string(d))
}

func (d DIDPeer) String() string {
	return string(d)
}

func (d DIDPeer) Suffix() (string, error) {
	split := strings.Split(string(d), DIDPeerPrefix+":")
	if len(split) != 2 {
		return "", errors.New("invalid did peer")
	}
	s := split[1]
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

func (DIDPeer) Method() did.Method {
	return did.PeerMethod
}

func buildDIDPeerFromEncoded(method int, encoded string) DIDPeer {
	return DIDPeer(fmt.Sprintf("%s:%d%s", DIDPeerPrefix, method, encoded))
}

type byValue struct {
	Key       string `json:"key"`
	Signature string `json:"sig"`
}

// PeerDelta https://identity.foundation/peer-did-method-spec/#backing-storage
type PeerDelta struct {
	Change string    `json:"change"` // <base64url encoding of a change fragment>,
	By     []byValue `json:"by"`     //  [ {"key": <id of key>, "sig": <signature value>} ... ],
	When   int64     `json:"when"`   // <ISO8601/RFC3339 UTC timestamp with at least second precision>
}

func (DIDPeer) Delta(_ DIDPeer) (*PeerDelta, error) {
	return nil, errors.Wrap(util.NotImplementedError, "peer:did delta")
}

// TODO: CRDT
// https://identity.foundation/peer-did-method-spec/#crdts

// Generates the key by types
func (DIDPeer) generateKeyByType(kt crypto.KeyType) (gocrypto.PublicKey, gocrypto.PrivateKey, error) {
	if !IsSupportedDIDPeerType(kt) {
		err := fmt.Errorf("%s : %s for did:peer", util.UnsupportedError, kt)
		return nil, nil, err
	}
	return crypto.GenerateKeyByKeyType(kt)
}

func (DIDPeer) IsValidPurpose(p PurposeType) bool {
	if _, ok := supportedDIDPeerPurposes[p]; ok {
		return true
	}
	return false
}

func (PeerMethod1) resolve(d did.DID, _ resolver.ResolutionOption) (*resolver.ResolutionResult, error) {
	if _, ok := d.(DIDPeer); !ok {
		return nil, errors.Wrap(util.CastingError, DIDPeerPrefix)
	}
	return nil, util.NotImplementedError
}

func (DIDPeer) buildVerificationMethod(data, id string) (*did.VerificationMethod, error) {
	_, keyType, err := did.DecodeMultibasePublicKeyWithType([]byte(data))
	if err != nil {
		return nil, err
	}

	vm := did.VerificationMethod{
		ID:                 string(id) + "#" + data[1:],
		Type:               keyType,
		Controller:         string(id),
		PublicKeyMultibase: data,
	}
	return &vm, nil
}

// PeerServiceBlockEncoded Remaps the service block for encoding
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
func (DIDPeer) encodeService(p did.Service) (string, error) {
	if p.ServiceEndpoint == nil {
		return "", errors.Wrap(util.UndefinedError, "service endpoint is not defined")
	}

	serviceBlock := PeerServiceBlockEncoded{
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
func (DIDPeer) checkValidPeerServiceBlock(s string) bool {
	if s[:2] != "."+string(PeerPurposeCapabilityServiceCode) {
		return false
	}
	return true
}

// Decodes a service block.
// Assumes that the service block has been stripped of any headers or identifiers.
func (d DIDPeer) decodeServiceBlock(s string) (*did.Service, error) {
	// check it starts with s.
	if !d.checkValidPeerServiceBlock(s) {
		return nil, errors.New("invalid string provided")
	}

	s2 := s[2:]

	// Remove the padding if present.
	padding := b64.NoPadding
	if s2[len(s2)-1] == '=' {
		padding = b64.StdPadding
	}
	encoder := b64.RawURLEncoding.WithPadding(padding)
	decoded, err := encoder.DecodeString(s2)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode service for did:peer")
	}

	var psbe PeerServiceBlockEncoded
	if err = json.Unmarshal(decoded, &psbe); err != nil {
		return nil, errors.Wrap(err, "could not decode JSON for peer service block")
	}
	serviceBlock := did.Service{
		Type:            psbe.ServiceType,
		ServiceEndpoint: psbe.ServiceEndpoint,
		RoutingKeys:     psbe.RoutingKeys,
		Accept:          psbe.Accept,
	}

	if serviceBlock.Type == PeerDIDCommMessagingAbbr {
		serviceBlock.Type = PeerDIDCommMessaging
	}

	return &serviceBlock, nil
}

type ServiceTypeAbbreviationMap map[string]string

func (d DIDPeer) GetMethodID() (string, error) {
	m := string(d[9])
	if peerMethodAvailable(m) {
		return m, nil
	}
	return "", fmt.Errorf("%s method not supported", m)
}

func peerMethodAvailable(m string) bool {
	switch m {
	case "0":
		// PeerMethod0
		return true
	case "1":
		// PeerMethod1
		return false
	case "2":
		// PeerMethod2
		return true
	default:
		return false
	}
}

// Encodes the public key provided using a multi-codec encoding.
func encodePublicKeyWithKeyMultiCodecType(kt crypto.KeyType, pubKey gocrypto.PublicKey) (string, error) {
	if !IsSupportedDIDPeerType(kt) {
		return "", errors.Wrap(util.UnsupportedError, "not a supported key type")
	}

	publicKey, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		return "", err
	}

	multiCodec, err := did.KeyTypeToMultiCodec(kt)
	if err != nil {
		return "", err
	}

	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(PeerEncNumBasis, codec)
	if err != nil {
		return "", err
	}

	return encoded, nil
}
