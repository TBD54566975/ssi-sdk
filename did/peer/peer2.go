package peer

import (
	gocrypto "crypto"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/util"
)

// Method2 Method 2: multiple inception key without doc
type Method2 struct {
	KT     crypto.KeyType
	Values []any
}

func (Method2) Method() did.Method {
	return did.PeerMethod
}

// Resolve Splits the DID string into element.
// Extract element purpose and decode each key or service.
// Insert each key or service into the document according to the designated pu
func (Method2) resolve(didDoc did.DID, _ resolution.Option) (*resolution.Result, error) {
	d, ok := didDoc.(DIDPeer)
	if !ok {
		return nil, errors.Wrap(util.CastingError, "did:peer")
	}

	// The '=' at the end is an artifact of the encoding, and will mess up the decoding
	// over the partials, so is removed.
	// https://identity.foundation/peer-did-method-spec/index.html#generation-method
	// ds := string(d)
	// if ds[len(ds)-1] == '=' {
	// 	d = DIDPeer(ds[:len(ds)-1])
	// }

	parsed, err := d.Suffix()
	if err != nil {
		return nil, err
	}

	entries := strings.Split(parsed, ".")
	if len(entries) == 0 {
		return nil, errors.New("no entries found")
	}

	doc := did.Document{
		Context: KnownContext,
		ID:      string(d),
	}

	for _, entry := range entries {
		serviceType := PurposeType(entry[0])
		switch serviceType {
		case PurposeCapabilityServiceCode:
			service, err := d.decodeServiceBlock("." + entry)
			if err != nil {
				return nil, err
			}
			service.ID = string(d) + "#didcommmessaging-0"
			doc.Services = append(doc.Services, *service)
		case PurposeEncryptionCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, errors.Wrap(err, "failed to build encryption code")
			}
			doc.KeyAgreement = append(doc.KeyAgreement, *vm)
		case PurposeVerificationCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, errors.Wrap(err, "failed to build validation code")
			}
			doc.Authentication = append(doc.Authentication, *vm)
		case PurposeCapabilityInvocationCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, errors.Wrap(err, "failed to build capabilities invocation code")
			}
			doc.CapabilityInvocation = append(doc.CapabilityInvocation, *vm)
		case PurposeCapabilityDelegationCode:
			vm, err := d.buildVerificationMethod(entry[1:], string(d))
			if err != nil {
				return nil, errors.Wrap(err, "failed to build capability delegation code")
			}
			doc.CapabilityDelegation = append(doc.CapabilityDelegation, *vm)
		default:
			return nil, errors.Wrap(util.UnsupportedError, string(entry[0]))
		}
	}
	return &resolution.Result{Document: doc}, nil
}

// Generate If numalgo == 2, the generation mode is similar to Method 0 (and therefore also did:key) with the ability
// to specify additional keys in the generated DID Document. This method is necessary when both an encryption key
// and a signing key are required.
// It determines the purpose implicitly by looking at the type of object:
// 1. Start with the did prefix did:peer:2
// 2. Construct a multibase encoded, multicodec-encoded form of each public key to be included.
// 3. Prefix each encoded key with a period character (.) and single character from the purpose codes table below.
// 4. Append the encoded key to the DID.
// 5. Encode and append a service type to the end of the peer DID if desired as described below.
func (m Method2) Generate() (*DIDPeer, error) {
	if len(m.Values) == 0 {
		// revive:disable-next-line:error-strings We do not want to change to error messages sent to clients.
		return nil, errors.New("no keys specified for did:peer. could not build.")
	}

	var didPeer DIDPeer
	var encoded string
	var err error

	for i, value := range m.Values {
		var enc string
		var purpose PurposeType

		switch tt := value.(type) {
		case did.Service:
			purpose = PurposeCapabilityServiceCode
			service := value.(did.Service)

			if i < len(m.Values)-1 {
				return nil, fmt.Errorf("failed to created did for %s. service must be appended last", "did:peer")
			}

			if !service.IsValid() {
				return nil, errors.New("service purpose provided but invalid service definition given")
			}

			enc, err = didPeer.encodeService(service)

			if err != nil {
				return nil, errors.Wrap(err, "could not encode service for did:peer")
			}

		case gocrypto.PublicKey:
			purpose = PurposeEncryptionCode
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

	didPeer = buildDIDPeerFromEncoded(2, encoded)

	return &didPeer, nil
}
