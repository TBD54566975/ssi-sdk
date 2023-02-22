package util

import (
	"fmt"
	"reflect"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// CredentialsFromInterface turn a generic cred into a known shape without maintaining the proof/signature wrapper
func CredentialsFromInterface(genericCred interface{}) (*credential.VerifiableCredential, error) {
	switch genericCred.(type) {
	case string:
		// JWT
		cred, err := signing.ParseVerifiableCredentialFromJWT(genericCred.(string))
		if err != nil {
			return nil, errors.Wrap(err, "could not parse credential from JWT")
		}
		return cred, nil
	case map[string]interface{}:
		// JSON
		var cred credential.VerifiableCredential
		credMapBytes, err := json.Marshal(genericCred.(map[string]interface{}))
		if err != nil {
			return nil, errors.Wrap(err, "could not marshal credential map")
		}
		if err = json.Unmarshal(credMapBytes, &cred); err != nil {
			return nil, errors.Wrap(err, "could not unmarshal credential map")
		}
		return &cred, nil
	case credential.VerifiableCredential:
		// VerifiableCredential
		cred := genericCred.(credential.VerifiableCredential)
		return &cred, nil
	default:
		return nil, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(genericCred).Kind().String())
	}
}

// ClaimAsJSON converts a claim with an unknown any into the go-json representation of that credential.
// claim can only be of type {string, map[string]interface, VerifiableCredential}.
func ClaimAsJSON(claim any) (map[string]interface{}, error) {
	switch c := claim.(type) {
	case map[string]interface{}:
		return c, nil
	default:
	}

	vc, err := CredentialsFromInterface(claim)
	if err != nil {
		return nil, errors.Wrap(err, "credential from interface")
	}
	vcData, err := json.Marshal(vc)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling credential")
	}
	var submittedClaim map[string]interface{}
	if err := json.Unmarshal(vcData, &submittedClaim); err != nil {
		return nil, errors.Wrap(err, "unmarshalling credential")
	}
	return submittedClaim, nil
}
