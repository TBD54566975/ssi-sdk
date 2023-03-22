package ion

import (
	"strings"

	"github.com/goccy/go-json"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
)

// InitialState is the initial state of a DID Document as defined in the spec
// https://identity.foundation/sidetree/spec/#long-form-did-uris
type InitialState struct {
	SuffixData SuffixData `json:"suffixData,omitempty"`
	Delta      Delta      `json:"delta,omitempty"`
}

// CreateLongFormDID generates a long form DID URI representation from a document, recovery, and update keys,
// intended to be the initial state of a DID Document. The method follows the guidelines in the spec:
// https://identity.foundation/sidetree/spec/#long-form-did-uris
func CreateLongFormDID(recoveryKey, updateKey crypto.PublicKeyJWK, document Document) (string, error) {
	createRequest, err := NewCreateRequest(recoveryKey, updateKey, document)
	if err != nil {
		return "", err
	}

	shortFormDID, err := CreateShortFormDID(createRequest.SuffixData)
	if err != nil {
		return "", err
	}

	b, _ := json.Marshal(createRequest.SuffixData)
	println(string(b))

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
