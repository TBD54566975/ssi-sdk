package key

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolver"
)

type KeyResolver struct{}

var _ resolver.Resolver = (*KeyResolver)(nil)

func (KeyResolver) Resolve(_ context.Context, id string, _ ...resolver.ResolutionOption) (*resolver.ResolutionResult, error) {
	if !strings.HasPrefix(id, KeyPrefix) {
		return nil, fmt.Errorf("not a id:key DID: %s", id)
	}
	didKey := DIDKey(id)
	doc, err := didKey.Expand()
	if err != nil {
		return nil, errors.Wrapf(err, "could not expand did:key DID: %s", id)
	}
	return &resolver.ResolutionResult{Document: *doc}, nil
}

func (KeyResolver) Methods() []did.Method {
	return []did.Method{did.KeyMethod}
}
