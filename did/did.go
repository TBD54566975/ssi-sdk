package did

import (
	"strings"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

// DID represents functionality common to all DIDs
type DID interface {
	// IsValid checks if the DID is compliant with its methods definition
	IsValid() bool
	// ToString Returns the string representation of the DID identifier (e.g. did:example:abcd)
	ToString() string
	// Parse provides the value of the DID without the method prefix
	Parse() (string, error)
}

// ParseDID provides the value of the DID without the method prefix
func ParseDID(did DID, prefix string) (string, error) {
	split := strings.Split(did.ToString(), prefix)
	if len(split) != 2 {
		return "", errors.Wrap(util.InvalidFormatError, "did is malformed")
	}
	return split[1], nil
}

type ResolutionOptions interface{}

// Resolver provides an interface for resolving DIDs as per the spec
// https://www.w3.org/TR/did-core/#did-resolution
type Resolver interface {
	Resolve(d DID, opts ResolutionOptions) (*DIDDocument, *DIDResolutionMetadata, *DIDDocumentMetadata, error)
}
