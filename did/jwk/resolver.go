package jwk

import (
	"context"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
)

type Resolver struct{}

var _ resolution.Resolver = (*Resolver)(nil)

func (Resolver) Resolve(_ context.Context, id string, _ ...resolution.ResolutionOption) (*resolution.ResolutionResult, error) {
	didJWK := JWK(id)
	doc, err := didJWK.Expand()
	if err != nil {
		return nil, errors.Wrap(err, "expanding did:jwk")
	}
	return &resolution.ResolutionResult{Document: *doc}, nil
}

func (Resolver) Methods() []did.Method {
	return []did.Method{did.JWKMethod}
}
