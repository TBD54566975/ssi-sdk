package key

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
)

type Resolver struct{}

var _ resolution.Resolver = (*Resolver)(nil)

func (Resolver) Resolve(_ context.Context, id string, _ ...resolution.Option) (*resolution.Result, error) {
	if !strings.HasPrefix(id, Prefix) {
		return nil, fmt.Errorf("not a id:key DID: %s", id)
	}
	didKey := DIDKey(id)
	doc, err := didKey.Expand()
	if err != nil {
		return nil, errors.Wrapf(err, "could not expand did:key DID: %s", id)
	}
	return &resolution.Result{Document: *doc}, nil
}

func (Resolver) Methods() []did.Method {
	return []did.Method{did.KeyMethod}
}
