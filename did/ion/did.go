package ion

import (
	"strings"

	"github.com/goccy/go-json"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type InitialState struct {
	SuffixData SuffixData `json:"suffixData,omitempty"`
	Delta      Delta      `json:"delta,omitempty"`
}

func CreateLongFormDID(recoveryKey, updateKey crypto.PublicKeyJWK, document Document) (string, error) {
	createRequest, err := NewCreateRequest(recoveryKey, updateKey, document)
	if err != nil {
		return "", err
	}

	shortFormDID, err := ShortFormDID(createRequest.SuffixData)
	if err != nil {
		return "", err
	}

	initialState := InitialState{
		Delta:      createRequest.Delta,
		SuffixData: createRequest.SuffixData,
	}

	initialStateBytesCanonical, err := CanonicalizeAny(initialState)
	if err != nil {
		logrus.WithError(err).Error("could not canonicalize long form DID suffix data")
		return "", err
	}
	encoded := Encode(initialStateBytesCanonical)
	return strings.Join([]string{shortFormDID, encoded}, ":"), nil
}

// ShortFormDID follows the process on did uri composition from the spec:
// https://identity.foundation/sidetree/spec/#did-uri-composition
func ShortFormDID(suffixData any) (string, error) {
	createOpSuffixDataCanonical, err := CanonicalizeAny(suffixData)
	if err != nil {
		logrus.WithError(err).Error("could not canonicalize suffix data")
		return "", err
	}
	hash, err := HashEncode(createOpSuffixDataCanonical)
	if err != nil {
		logrus.WithError(err).Error("could not generate multihash for DID URI")
		return "", err
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
		return "", nil, errors.Wrap(err, "could not decode long form URI")
	}
	var initialState InitialState
	if err = json.Unmarshal(decoded, &initialState); err != nil {
		return "", nil, errors.Wrap(err, "could not unmarshal long form URI")
	}
	return strings.Join(split[0:3], ":"), &initialState, nil
}
