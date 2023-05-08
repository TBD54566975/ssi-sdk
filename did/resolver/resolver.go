package resolver

import (
	"context"
	gocrypto "crypto"
	"fmt"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/did"
)

// ResolutionOption https://www.w3.org/TR/did-spec-registries/#did-resolution-options
type ResolutionOption any

// Resolver provides an interface for resolving DIDs as per the spec https://www.w3.org/TR/did-core/#did-resolution
type Resolver interface {
	// Resolve Attempts to resolve a DID for a given method
	Resolve(ctx context.Context, id string, opts ...ResolutionOption) (*ResolutionResult, error)
	// Methods returns all methods that can be resolved by this resolver.
	Methods() []did.Method
}

// MultiMethodResolver resolves a DID. The current implementation ssk-sdk does not have a universal resolver:
// https://github.com/decentralized-identity/universal-resolver
// In its place, this method attempts to resolve DID methods that can be resolved without relying on additional services.
type MultiMethodResolver struct {
	resolvers map[did.Method]Resolver
	methods   []did.Method
}

var _ Resolver = (*MultiMethodResolver)(nil)

func NewResolver(resolvers ...Resolver) (*MultiMethodResolver, error) {
	r := make(map[did.Method]Resolver)
	var methods []did.Method
	for _, resolver := range resolvers {
		method := resolver.Methods()
		for _, m := range method {
			if _, ok := r[m]; ok {
				return nil, fmt.Errorf("duplicate resolver for method: %s", m)
			}
			r[m] = resolver
			methods = append(methods, m)
		}
	}
	return &MultiMethodResolver{resolvers: r, methods: methods}, nil
}

// Resolve attempts to resolve a DID for a given method
func (dr MultiMethodResolver) Resolve(ctx context.Context, did string, opts ...ResolutionOption) (*ResolutionResult, error) {
	method, err := GetMethodForDID(did)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get method for DID before resolving")
	}
	if resolver, ok := dr.resolvers[method]; ok {
		return resolver.Resolve(ctx, did, opts)
	}
	return nil, fmt.Errorf("unsupported method: %s", method)
}

func (dr MultiMethodResolver) Methods() []did.Method {
	return dr.methods
}

// GetMethodForDID provides the method for the given did string
func GetMethodForDID(id string) (did.Method, error) {
	split := strings.Split(id, ":")
	if len(split) < 3 {
		return "", fmt.Errorf("not a valid did: %s", id)
	}
	return did.Method(split[1]), nil
}

// ParseDIDResolution attempts to parse a DID Resolution Result or a DID Document
func ParseDIDResolution(resolvedDID []byte) (*ResolutionResult, error) {
	if len(resolvedDID) == 0 {
		return nil, errors.New("cannot parse empty resolved DID")
	}

	// first try to parse as a DID Resolver Result
	var result ResolutionResult
	if err := json.Unmarshal(resolvedDID, &result); err == nil {
		if result.IsEmpty() {
			return nil, errors.New("empty DID Resolution Result")
		}
		return &result, err
	}

	// next try to parse as a DID Document
	var didDoc did.Document
	if err := json.Unmarshal(resolvedDID, &didDoc); err == nil {
		if didDoc.IsEmpty() {
			return nil, errors.New("empty DID Document")
		}
		return &ResolutionResult{Document: didDoc}, nil
	}

	// if that fails we don't know what it is!
	return nil, errors.New("could not parse DID Resolution Result or DID Document")
}

// ResolveKeyForDID resolves a public key from a DID for a given KID.
func ResolveKeyForDID(ctx context.Context, resolver Resolver, id, kid string) (gocrypto.PublicKey, error) {
	if resolver == nil {
		return nil, errors.New("resolver cannot be empty")
	}
	resolved, err := resolver.Resolve(ctx, id, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving DID: %s", id)
	}

	// next, get the verification information (key) from the did document
	pubKey, err := did.GetKeyFromVerificationMethod(resolved.Document, kid)
	if err != nil {
		return nil, errors.Wrapf(err, "getting verification information from DID Document: %s", id)
	}
	return pubKey, err
}
