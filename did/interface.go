package did

import (
	"strings"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

// TODO: All DID's MUST do X?
// Define the interface more clearly
type DID interface {
	IsValid() bool
	Resolve() (*DIDDocument, error)
	ToString() string
}

type DIDURL interface {
	Dereference() interface{}
}

func ParseDID(did DID, prefix string) (string, error) {
	split := strings.Split(did.ToString(), prefix)
	if len(split) != 2 {
		return "", errors.Wrap(util.INVALID_FORMAT_ERROR, "did can't split correctly")
	}
	return split[1], nil
}
