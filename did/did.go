package did

import (
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

type (
	Method string
)

const (
	KeyMethod  Method = "key"
	PeerMethod Method = "peer"
	PKHMethod  Method = "pkh"
	WebMethod  Method = "web"
)

// DID represents functionality common to all DIDs
type DID interface {
	// IsValid checks if the DID is compliant with its methods definition
	IsValid() bool
	// ToString Returns the string representation of the DID identifier (e.g. did:example:abcd)
	ToString() string
	// Suffix provides the value of the DID without the method prefix
	Suffix() (string, error)
	// Method provides the method for the DID
	Method() Method
}

// ResolutionOptions https://www.w3.org/TR/did-spec-registries/#did-resolution-options
type ResolutionOptions interface{}

// Resolution provides an interface for resolving DIDs as per the spec https://www.w3.org/TR/did-core/#did-resolution
type Resolution interface {
	// Resolve Attempts to resolve a DID for a given method
	Resolve(did string, opts ResolutionOptions) (*DIDResolutionResult, error)
	// Method provides the method for the given resolution implementation
	Method() Method
}

// Resolver resolves a DID. The current implementation ssk-sdk does not have a universal resolver:
// https://github.com/decentralized-identity/universal-resolver
// In its place, this method attempts to resolve DID methods that can be resolved without relying on additional services.
type Resolver struct {
	resolvers map[Method]Resolution
	methods   []Method
}

func NewResolver(resolvers ...Resolution) (*Resolver, error) {
	r := make(map[Method]Resolution)
	var methods []Method
	for _, resolver := range resolvers {
		method := resolver.Method()
		if _, ok := r[method]; ok {
			return nil, util.LoggingNewError(fmt.Sprintf("duplicate resolver for method: %s", method))
		}
		r[method] = resolver
		methods = append(methods, method)
	}
	return &Resolver{resolvers: r, methods: methods}, nil
}

// Resolve attempts to resolve a DID for a given method
func (dr Resolver) Resolve(did string, opts ...ResolutionOptions) (*DIDResolutionResult, error) {
	method, err := getMethodForDID(did)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get method for DID before resolving")
	}
	if resolver, ok := dr.resolvers[method]; ok {
		return resolver.Resolve(did, opts)
	}
	return nil, util.LoggingNewError(fmt.Sprintf("unsupported method: %s", method))
}

func (dr Resolver) SupportedMethods() []Method {
	return dr.methods
}

func getMethodForDID(did string) (Method, error) {
	split := strings.Split(did, ":")
	if len(split) < 3 {
		return "", fmt.Errorf("not a valid did: %s", did)
	}
	return Method(split[1]), nil
}
