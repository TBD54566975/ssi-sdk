package web

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

func (Resolver) Methods() []did.Method {
	return []did.Method{did.WebMethod}
}

// Resolve fetches and returns the Document from the expected URL
// specification: https://w3c-ccg.github.io/did-method-web/#read-resolve
func (Resolver) Resolve(ctx context.Context, id string, _ ...resolution.Option) (*resolution.Result, error) {
	if !strings.HasPrefix(id, Prefix) {
		return nil, fmt.Errorf("not a did:web DID: %s", id)
	}
	didWeb := DIDWeb(id)
	doc, err := didWeb.Resolve(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving did:web DID: %s", id)
	}
	return &resolution.Result{Document: *doc}, nil
}
