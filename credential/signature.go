package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolver"

	"github.com/pkg/errors"
)

// VerifyCredentialSignature verifies the signature of a credential of any type
// TODO(gabe) support other types of credentials https://github.com/TBD54566975/ssi-sdk/issues/352
func VerifyCredentialSignature(ctx context.Context, genericCred any, resolver resolver.Resolver) (bool, error) {
	if genericCred == nil {
		return false, errors.New("credential cannot be empty")
	}
	if resolver == nil {
		return false, errors.New("resolver cannot be empty")
	}
	switch genericCred.(type) {
	case *VerifiableCredential, VerifiableCredential, map[string]any:
		_, token, cred, err := ToCredential(genericCred)
		if err != nil {
			return false, errors.Wrap(err, "error converting credential from generic type")
		}
		if token != nil {
			return false, errors.New("JWT credentials must include a signature to be verified")
		}
		if cred.IsEmpty() {
			return false, errors.New("credential cannot be empty")
		}
		if cred.GetProof() == nil {
			return false, errors.New("credential must have a proof")
		}
		return false, errors.New("data integrity signature verification not yet implemented")
	case []byte:
		// turn it into a string and try again
		return VerifyCredentialSignature(ctx, string(genericCred.([]byte)), resolver)
	case string:
		// could be a Data Integrity credential
		var cred VerifiableCredential
		if err := json.Unmarshal([]byte(genericCred.(string)), &cred); err == nil {
			return VerifyCredentialSignature(ctx, cred, resolver)
		}

		// could be a JWT
		return VerifyJWTCredential(genericCred.(string), resolver)
	}
	return false, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(genericCred).Kind().String())
}

// VerifyJWTCredential verifies the signature of a JWT credential after parsing it to resolve the issuer DID
// The issuer DID is resolver from the provided resolver, and used to find the issuer's public key matching
// the KID in the JWT header.
func VerifyJWTCredential(cred string, resolver resolver.Resolver) (bool, error) {
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
	credVerifier, err := jwx.NewJWXVerifier(issuerDID.ID, issuerKID, issuerKey)
	if err != nil {
		return false, errors.Wrapf(err, "error constructing verifier for credential<%s>", token.JwtID())
	}
	// verify the signature
	if err = credVerifier.Verify(cred); err != nil {
		return false, errors.Wrapf(err, "error verifying credential<%s>", token.JwtID())
	}
	return true, nil
}
