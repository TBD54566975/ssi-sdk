package pkh

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolver"
)

type Resolver struct{}

var _ resolver.Resolver = (*Resolver)(nil)

func (Resolver) Resolve(_ context.Context, id string, _ ...resolver.ResolutionOption) (*resolver.ResolutionResult, error) {
	if !strings.HasPrefix(id, DIDPKHPrefix) {
		return nil, fmt.Errorf("not a did:pkh DID: %s", id)
	}
	didPKH := PKH(id)
	doc, err := didPKH.Expand()
	if err != nil {
		return nil, errors.Wrapf(err, "could not expand did:pkh DID: %s", id)
	}
	return &resolver.ResolutionResult{Document: *doc}, nil
}

func (Resolver) Methods() []did.Method {
	return []did.Method{did.PKHMethod}
}
