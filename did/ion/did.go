package ion

import (
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/goccy/go-json"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
)

// InitialState is the initial state of a DID Document as defined in the spec
// https://identity.foundation/sidetree/spec/#long-form-did-uris
type InitialState struct {
	SuffixData SuffixData `json:"suffixData,omitempty"`
	Delta      Delta      `json:"delta,omitempty"`
}

func (is InitialState) ToDIDStrings() (shortFormDID string, longFormDID string, err error) {
	shortFormDID, err = CreateShortFormDID(is.SuffixData)
	if err != nil {
		return shortFormDID, longFormDID, err
	}
	initialStateBytesCanonical, err := CanonicalizeAny(is)
	if err != nil {
		err = errors.Wrap(err, "canonicalizing long form DID suffix data")
		return shortFormDID, longFormDID, err
	}
	encoded := Encode(initialStateBytesCanonical)
	longFormDID = strings.Join([]string{shortFormDID, encoded}, ":")
	return shortFormDID, longFormDID, nil
}

// CreateLongFormDID generates a long form DID URI representation from a document, recovery, and update keys,
// intended to be the initial state of a DID Document. The method follows the guidelines in the spec:
// https://identity.foundation/sidetree/spec/#long-form-did-uris
func CreateLongFormDID(recoveryKey, updateKey jwx.PublicKeyJWK, document Document) (string, error) {
	createRequest, err := NewCreateRequest(recoveryKey, updateKey, document)
	if err != nil {
		return "", err
	}
	shortFormDID, err := CreateShortFormDID(createRequest.SuffixData)
	if err != nil {
		return "", err
	}
	is := InitialState{
		Delta:      createRequest.Delta,
		SuffixData: createRequest.SuffixData,
	}
	initialStateBytesCanonical, err := CanonicalizeAny(is)
	if err != nil {
		return "", errors.Wrap(err, "canonicalizing long form DID suffix data")
	}
	encoded := Encode(initialStateBytesCanonical)
	return strings.Join([]string{shortFormDID, encoded}, ":"), nil
}

// IsLongFormDID checks if a string is a long form DID URI
func IsLongFormDID(maybeLongFormDID string) bool {
	return strings.Count(maybeLongFormDID, ":") == 3
}

// DecodeLongFormDID decodes a long form DID into a short form DID and
// its create operation suffix data
func DecodeLongFormDID(longFormDID string) (string, *InitialState, error) {
	split := strings.Split(longFormDID, ":")
	if len(split) != 4 {
		return "", nil, errors.New("invalid long form URI")
	}
	if split[0] != "did" || (did.Method(split[1]) != did.IONMethod) {
		return "", nil, errors.New("not a valid ion DID")
	}
	decoded, err := Decode(split[3])
	if err != nil {
		return "", nil, errors.Wrap(err, "decoding long form URI")
	}
	var initialState InitialState
	if err = json.Unmarshal(decoded, &initialState); err != nil {
		return "", nil, errors.Wrap(err, "unmarshalling long form URI")
	}
	return strings.Join(split[0:3], ":"), &initialState, nil
}

// CreateShortFormDID follows the process on did uri composition from the spec:
// https://identity.foundation/sidetree/spec/#did-uri-composition, used to generate a short form DID URI,
// which is most frequently used in the protocol and when sharing out ION DIDs.
func CreateShortFormDID(suffixData any) (string, error) {
	createOpSuffixDataCanonical, err := CanonicalizeAny(suffixData)
	if err != nil {
		return "", errors.Wrap(err, "canonicalizing suffix data")
	}
	hash, err := HashEncode(createOpSuffixDataCanonical)
	if err != nil {
		return "", errors.Wrap(err, "generating multihash for DID URI")
	}
	return strings.Join([]string{"did", did.IONMethod.String(), hash}, ":"), nil
}

// LongToShortFormDID returns the short form DID from a long form DID
func LongToShortFormDID(longFormDID string) (string, error) {
	shortFormDID, _, err := DecodeLongFormDID(longFormDID)
	if err != nil {
		return "", errors.Wrap(err, "decoding long form DID")
	}
	return shortFormDID, nil
}

// PatchesToDIDDocument applies a list of sidetree state patches in order resulting in a DID Document.
func PatchesToDIDDocument(shortFormDID, longFormDID string, patches []Patch) (*did.Document, error) {
	if len(patches) == 0 {
		return nil, errors.New("no patches to apply")
	}
	if shortFormDID == "" {
		return nil, errors.New("short form DID is required")
	}
	doc := did.Document{
		Context: []any{"https://www.w3.org/ns/did/v1", map[string]any{
			"@base": longFormDID,
		}},
		ID: longFormDID,
	}
	for _, patch := range patches {
		switch patch.GetAction() {
		case AddServices:
			addServicePatch := patch.(AddServicesAction)
			for _, s := range addServicePatch.Services {
				s := s
				s.ID = canonicalID(s.ID)
				doc.Services = append(doc.Services, s)
			}
		case RemoveServices:
			removeServicePatch := patch.(RemoveServicesAction)
			for _, id := range removeServicePatch.IDs {
				id := canonicalID(id)
				for i, service := range doc.Services {
					if service.ID == id {
						doc.Services = append(doc.Services[:i], doc.Services[i+1:]...)
					}
				}
			}
		case AddPublicKeys:
			addKeyPatch := patch.(AddPublicKeysAction)
			gotDoc, err := addPublicKeysPatch(doc, addKeyPatch)
			if err != nil {
				return nil, err
			}
			doc = *gotDoc
		case RemovePublicKeys:
			removeKeyPatch := patch.(RemovePublicKeysAction)
			gotDoc, err := removePublicKeysPatch(doc, removeKeyPatch)
			if err != nil {
				return nil, err
			}
			doc = *gotDoc
		case Replace:
			replacePatch := patch.(ReplaceAction)
			gotDoc, err := replaceActionPatch(doc, replacePatch)
			if err != nil {
				return nil, err
			}
			doc = *gotDoc
		default:
			return nil, fmt.Errorf("unknown patch type: %T", patch)
		}
	}
	return &doc, nil
}

func replaceActionPatch(doc did.Document, patch ReplaceAction) (*did.Document, error) {
	// first zero out all public keys and services
	doc.VerificationMethod = nil
	doc.Authentication = nil
	doc.AssertionMethod = nil
	doc.KeyAgreement = nil
	doc.CapabilityInvocation = nil
	doc.CapabilityDelegation = nil
	doc.Services = nil

	// now add back what the patch includes
	gotDoc, err := addPublicKeysPatch(doc, AddPublicKeysAction{PublicKeys: patch.Document.PublicKeys})
	if err != nil {
		return nil, err
	}
	doc = *gotDoc
	for _, service := range patch.Document.Services {
		s := service
		s.ID = canonicalID(s.ID)
		doc.Services = append(doc.Services, s)
	}
	return &doc, nil
}

func addPublicKeysPatch(doc did.Document, patch AddPublicKeysAction) (*did.Document, error) {
	for _, key := range patch.PublicKeys {
		currKey := key
		currKey.ID = canonicalID(currKey.ID)
		doc.VerificationMethod = append(doc.VerificationMethod, did.VerificationMethod{
			ID:           currKey.ID,
			Type:         cryptosuite.LDKeyType(currKey.Type),
			Controller:   doc.ID,
			PublicKeyJWK: &currKey.PublicKeyJWK,
		})
		for _, purpose := range currKey.Purposes {
			switch purpose {
			case did.Authentication:
				doc.Authentication = append(doc.Authentication, currKey.ID)
			case did.AssertionMethod:
				doc.AssertionMethod = append(doc.AssertionMethod, currKey.ID)
			case did.KeyAgreement:
				doc.KeyAgreement = append(doc.KeyAgreement, currKey.ID)
			case did.CapabilityInvocation:
				doc.CapabilityInvocation = append(doc.CapabilityInvocation, currKey.ID)
			case did.CapabilityDelegation:
				doc.CapabilityDelegation = append(doc.CapabilityDelegation, currKey.ID)
			default:
				return nil, fmt.Errorf("unknown key purpose: %s:%s", currKey.ID, purpose)
			}
		}
	}
	return &doc, nil
}

func canonicalID(id string) string {
	if strings.Contains(id, "#") {
		return id
	}
	return "#" + id
}

func removePublicKeysPatch(doc did.Document, patch RemovePublicKeysAction) (*did.Document, error) {
	for _, id := range patch.IDs {
		id := canonicalID(id)
		removed := false
		for i, key := range doc.VerificationMethod {
			if key.ID != id {
				continue
			}
			doc.VerificationMethod = append(doc.VerificationMethod[:i], doc.VerificationMethod[i+1:]...)
			removed = true

			// TODO(gabe): in the future handle the case where the value is not a simple ID
			// remove from all other key lists
			for j, a := range doc.Authentication {
				if a == id {
					doc.Authentication = append(doc.Authentication[:j], doc.Authentication[j+1:]...)
				}
			}
			for j, am := range doc.AssertionMethod {
				if am == id {
					doc.AssertionMethod = append(doc.AssertionMethod[:j], doc.AssertionMethod[j+1:]...)
				}
			}
			for j, ka := range doc.KeyAgreement {
				if ka == id {
					doc.KeyAgreement = append(doc.KeyAgreement[:j], doc.KeyAgreement[j+1:]...)
				}
			}
			for j, ci := range doc.CapabilityInvocation {
				if ci == id {
					doc.CapabilityInvocation = append(doc.CapabilityInvocation[:j], doc.CapabilityInvocation[j+1:]...)
				}
			}
			for j, cd := range doc.CapabilityDelegation {
				if cd == id {
					doc.CapabilityDelegation = append(doc.CapabilityDelegation[:j], doc.CapabilityDelegation[j+1:]...)
				}
			}
		}
		if !removed {
			return nil, fmt.Errorf("could not find key with id %s", id)
		}
	}
	return &doc, nil
}
