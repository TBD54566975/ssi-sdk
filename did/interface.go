package did

import (
	"strings"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

// DID represents functionality common to all DIDs
type DID interface {
	IsValid() bool
	ToString() string
	Parse() (string, error)
}

func ParseDID(did DID, prefix string) (string, error) {
	split := strings.Split(did.ToString(), prefix)
	if len(split) != 2 {
		return "", errors.Wrap(util.InvalidFormatError, "did can't split correctly")
	}
	return split[1], nil
}

type ResolutionOptions interface{}

type DIDResolver interface {
	Resolve(d DID, opts ResolutionOptions) (*DIDDocument, *DIDResolutionMetadata, *DIDDocumentMetadata, error)
}
