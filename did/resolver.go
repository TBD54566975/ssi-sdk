package did

import (
	"context"
	"fmt"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// ResolutionOption https://www.w3.org/TR/did-spec-registries/#did-resolution-options
type ResolutionOption any

// Resolver provides an interface for resolving DIDs as per the spec https://www.w3.org/TR/did-core/#did-resolution
type Resolver interface {
	// Resolve Attempts to resolve a DID for a given method
	Resolve(ctx context.Context, did string, opts ...ResolutionOption) (*ResolutionResult, error)
	// Method provides the method for the given resolution implementation
	Method() Method
}

// MultiMethodResolver resolves a DID. The current implementation ssk-sdk does not have a universal resolver:
// https://github.com/decentralized-identity/universal-resolver
// In its place, this method attempts to resolve DID methods that can be resolved without relying on additional services.
type MultiMethodResolver struct {
	resolvers map[Method]Resolver
	methods   []Method
}

func NewResolver(resolvers ...Resolver) (*MultiMethodResolver, error) {
	r := make(map[Method]Resolver)
	var methods []Method
	for _, resolver := range resolvers {
		method := resolver.Method()
		if _, ok := r[method]; ok {
			return nil, fmt.Errorf("duplicate resolver for method: %s", method)
		}
		r[method] = resolver
		methods = append(methods, method)
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

func (dr MultiMethodResolver) SupportedMethods() []Method {
	return dr.methods
}

// GetMethodForDID provides the method for the given did string
func GetMethodForDID(did string) (Method, error) {
	split := strings.Split(did, ":")
	if len(split) < 3 {
		return "", fmt.Errorf("not a valid did: %s", did)
	}
	return Method(split[1]), nil
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
	var didDoc Document
	if err := json.Unmarshal(resolvedDID, &didDoc); err == nil {
		if didDoc.IsEmpty() {
			return nil, errors.New("empty DID Document")
		}
		return &ResolutionResult{
			Document: didDoc,
		}, nil
	}

	// if that fails we don't know what it is!
	return nil, errors.New("could not parse DID Resolution Result or DID Document")
}
