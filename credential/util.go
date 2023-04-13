package credential

import (
	"fmt"
	"reflect"

	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
)

// ToCredential turn a generic cred into its known object model
func ToCredential(genericCred any) (jws.Headers, jwt.Token, *VerifiableCredential, error) {
	switch genericCred.(type) {
	case *VerifiableCredential:
		return nil, nil, genericCred.(*VerifiableCredential), nil
	case VerifiableCredential:
		verifiableCredential := genericCred.(VerifiableCredential)
		return nil, nil, &verifiableCredential, nil
	case string:
		// JWT
		return ParseVerifiableCredentialFromJWT(genericCred.(string))
	case map[string]any:
		// VC or JWTVC JSON
		credJSON := genericCred.(map[string]any)
		credMapBytes, marshalErr := json.Marshal(credJSON)
		if marshalErr != nil {
			return nil, nil, nil, errors.Wrap(marshalErr, "marshalling credential map")
		}

		// first try as a VC object
		var cred VerifiableCredential
		if err := json.Unmarshal(credMapBytes, &cred); err != nil || cred.IsEmpty() {
			// if that fails, try as a JWT
			_, vcFromJWT, err := VCJWTJSONToVC(credMapBytes)
			if err != nil {
				return nil, nil, nil, errors.Wrap(err, "parsing generic credential as either VC or JWT")
			}
			return nil, nil, vcFromJWT, nil
		}
		return nil, nil, &cred, nil
	}
	return nil, nil, nil, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(genericCred).Kind().String())
}

// ToCredentialJSONMap turn a generic cred into a JSON object
func ToCredentialJSONMap(genericCred any) (map[string]any, error) {
	switch genericCred.(type) {
	case map[string]any:
		return genericCred.(map[string]any), nil
	case string:
		// JWT
		_, token, _, parseErr := ParseVerifiableCredentialFromJWT(genericCred.(string))
		if parseErr != nil {
			return nil, errors.Wrap(parseErr, "parsing credential from JWT")
		}
		// marshal it into a JSON map
		tokenJSONBytes, marshalErr := json.Marshal(token)
		if marshalErr != nil {
			return nil, errors.Wrap(marshalErr, "marshaling credential JWT")
		}
		var credJSON map[string]any
		if err := json.Unmarshal(tokenJSONBytes, &credJSON); err != nil {
			return nil, errors.Wrap(err, "unmarshalling credential JWT")
		}
		return credJSON, nil
	case VerifiableCredential, *VerifiableCredential:
		credJSONBytes, marshalErr := json.Marshal(genericCred)
		if marshalErr != nil {
			return nil, errors.Wrap(marshalErr, "marshalling credential object")
		}
		var credJSON map[string]any
		if err := json.Unmarshal(credJSONBytes, &credJSON); err != nil {
			return nil, errors.Wrap(err, "unmarshalling credential object")
		}
		return credJSON, nil
	}
	return nil, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(genericCred).Kind().String())
}

// VCJWTJSONToVC converts a JSON representation of a VC JWT into a VerifiableCredential
func VCJWTJSONToVC(vcJWTJSON []byte) (jwt.Token, *VerifiableCredential, error) {
	// next, try to turn it into a JWT to check if it's a VC JWT
	token, err := jwt.Parse(vcJWTJSON, jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, errors.Wrap(err, "coercing generic cred to JWT")
	}
	cred, err := ParseVerifiableCredentialFromToken(token)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing credential from token")
	}
	return token, cred, nil
}
