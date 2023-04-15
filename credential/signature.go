package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
)

// VerifyCredentialSignature verifies the signature of a credential of any type
// TODO(gabe) support other types of credentials https://github.com/TBD54566975/ssi-sdk/issues/352
func VerifyCredentialSignature(ctx context.Context, genericCred any, resolver did.Resolver) (bool, error) {
	if genericCred == nil {
		return false, errors.New("credential cannot be empty")
	}
	if resolver == nil {
		return false, errors.New("resolver cannot be empty")
	}
	switch genericCred.(type) {
	case *VerifiableCredential:
		return VerifyCredentialSignature(ctx, *genericCred.(*VerifiableCredential), resolver)
	case VerifiableCredential:
		cred := genericCred.(VerifiableCredential)
		if cred.IsEmpty() {
			return false, errors.New("credential cannot be empty")
		}
		if cred.GetProof() == nil {
			return false, errors.New("credential must have a proof")
		}
		return false, errors.New("data integrity signature verification not yet implemented")
	case []byte:
		// could be a JWT
		verified, err := VerifyCredentialSignature(ctx, string(genericCred.([]byte)), resolver)
		if err == nil {
			return verified, err
		}

		// could also be a vc
		var cred VerifiableCredential
		if err = json.Unmarshal(genericCred.([]byte), &cred); err != nil {
			return false, errors.Wrap(err, "unmarshalling generic credential")
		}
		return VerifyCredentialSignature(ctx, cred, resolver)
	case string:
		// JWT
		return VerifyJWTCredential(genericCred.(string), resolver)
	case map[string]any:
		// VC or JWTVC JSON
		credJSON := genericCred.(map[string]any)
		credMapBytes, err := json.Marshal(credJSON)
		if err != nil {
			return false, errors.Wrap(err, "marshalling generic credential")
		}

		// first try as a VC object
		var cred VerifiableCredential
		if err = json.Unmarshal(credMapBytes, &cred); err == nil && !cred.IsEmpty() {
			return VerifyCredentialSignature(ctx, cred, resolver)
		}

		// if that fails, try as a JWT
		if _, _, _, err := VCJWTJSONToVC(credMapBytes); err == nil {
			return false, errors.New("JWT credentials must include a signature to be verified")
		}
	}
	return false, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(genericCred).Kind().String())
}

// VerifyJWTCredential verifies the signature of a JWT credential after parsing it to resolve the issuer DID
// The issuer DID is resolver from the provided resolver, and used to find the issuer's public key matching
// the KID in the JWT header.
func VerifyJWTCredential(cred string, resolver did.Resolver) (bool, error) {
	if cred == "" {
		return false, errors.New("credential cannot be empty")
	}
	if resolver == nil {
		return false, errors.New("resolver cannot be empty")
	}
	headers, token, _, err := ParseVerifiableCredentialFromJWT(cred)
	if err != nil {
		return false, errors.Wrap(err, "parsing JWT")
	}

	// get key to verify the credential with
	issuerKID := headers.KeyID()
	if issuerKID == "" {
		return false, errors.Errorf("missing kid in header of credential<%s>", token.JwtID())
	}
	issuerDID, err := resolver.Resolve(context.Background(), token.Issuer())
	if err != nil {
		return false, errors.Wrapf(err, "error getting issuer DID<%s> to verify credential<%s>", token.Issuer(), token.JwtID())
	}
	issuerKey, err := did.GetKeyFromVerificationMethod(issuerDID.Document, issuerKID)
	if err != nil {
		return false, errors.Wrapf(err, "error getting key to verify credential<%s>", token.JwtID())
	}

	// construct a verifier
	credVerifier, err := crypto.NewJWTVerifier(issuerDID.ID, issuerKey)
	if err != nil {
		return false, errors.Wrapf(err, "error constructing verifier for credential<%s>", token.JwtID())
	}
	// verify the signature
	if err = credVerifier.Verify(cred); err != nil {
		return false, errors.Wrapf(err, "error verifying credential<%s>", token.JwtID())
	}
	return true, nil
}
