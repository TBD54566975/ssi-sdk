package parsing

import (
	"fmt"
	"reflect"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
)

// ToCredential turn a generic cred into its known object model
func ToCredential(genericCred any) (jws.Headers, jwt.Token, *credential.VerifiableCredential, error) {
	switch typedCred := genericCred.(type) {
	case []byte:
		// could be a JWT
		headers, token, vcFromJWT, err := ToCredential(string(typedCred))
		if err == nil {
			return headers, token, vcFromJWT, err
		}

		// could also be a vc
		var cred credential.VerifiableCredential
		if err = json.Unmarshal(genericCred.([]byte), &cred); err != nil {
			return nil, nil, nil, errors.Wrap(err, "unmarshalling credential object")
		}
		return ToCredential(cred)
	case *credential.VerifiableCredential:
		return nil, nil, typedCred, nil
	case credential.VerifiableCredential:
		return nil, nil, &typedCred, nil
	case string:
		// first try the case where the string is JSON of a VC object
		var cred credential.VerifiableCredential
		if err := json.Unmarshal([]byte(typedCred), &cred); err == nil {
			return nil, nil, &cred, nil
		}

		// next try it as a JWT
		return integrity.ParseVerifiableCredentialFromJWT(typedCred)
	case map[string]any:
		// VC or JWTVC JSON
		credMapBytes, err := json.Marshal(typedCred)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, "marshalling credential map")
		}

		// first try as a VC object
		var cred credential.VerifiableCredential
		if err = json.Unmarshal(credMapBytes, &cred); err == nil && !cred.IsEmpty() {
			return nil, nil, &cred, nil
		}

		// if that fails, try as a JWT
		headers, token, vcFromJWT, err := VCJWTJSONToVC(credMapBytes)
		if err != nil {
			return nil, nil, nil, errors.Wrap(err, "parsing generic credential as either VC or JWT")
		}
		return headers, token, vcFromJWT, nil
	}
	return nil, nil, nil, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(genericCred).Kind().String())
}

// ToCredentialJSONMap turn a generic cred into a JSON object
func ToCredentialJSONMap(genericCred any) (map[string]any, error) {
	switch typedCred := genericCred.(type) {
	case []byte:
		// could be a JWT
		credJSON, err := ToCredentialJSONMap(string(typedCred))
		if err == nil {
			return credJSON, err
		}

		// could also be a vc
		var cred credential.VerifiableCredential
		if err = json.Unmarshal(typedCred, &cred); err != nil {
			return nil, errors.Wrap(err, "unmarshalling credential object")
		}
		return ToCredentialJSONMap(cred)
	case map[string]any:
		return typedCred, nil
	case string:
		// first try the case where the string is JSON of a VC object
		var credJSON map[string]any
		if err := json.Unmarshal([]byte(typedCred), &credJSON); err == nil {
			return credJSON, nil
		}

		// next try it as a JWT
		_, token, _, err := integrity.ParseVerifiableCredentialFromJWT(typedCred)
		if err != nil {
			return nil, errors.Wrap(err, "parsing credential from JWT")
		}
		// marshal it into a JSON map
		tokenJSONBytes, err := json.Marshal(token)
		if err != nil {
			return nil, errors.Wrap(err, "marshaling credential JWT")
		}
		if err = json.Unmarshal(tokenJSONBytes, &credJSON); err != nil {
			return nil, errors.Wrap(err, "unmarshalling credential JWT")
		}
		return credJSON, nil
	case credential.VerifiableCredential, *credential.VerifiableCredential:
		credJSONBytes, err := json.Marshal(typedCred)
		if err != nil {
			return nil, errors.Wrap(err, "marshalling credential object")
		}
		var credJSON map[string]any
		if err = json.Unmarshal(credJSONBytes, &credJSON); err != nil {
			return nil, errors.Wrap(err, "unmarshalling credential object")
		}
		return credJSON, nil
	}
	return nil, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(genericCred).Kind().String())
}

// VCJWTJSONToVC converts a JSON representation of a VC JWT into a VerifiableCredential
func VCJWTJSONToVC(vcJWTJSON []byte) (jws.Headers, jwt.Token, *credential.VerifiableCredential, error) {
	// next, try to turn it into a JWT to check if it's a VC JWT
	token, err := jwt.Parse(vcJWTJSON, jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "coercing generic cred to JWT")
	}

	// get headers
	headers, err := jwx.GetJWSHeaders(vcJWTJSON)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not get JWT headers")
	}

	cred, err := integrity.ParseVerifiableCredentialFromToken(token)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parsing credential from token")
	}
	return headers, token, cred, nil
}
