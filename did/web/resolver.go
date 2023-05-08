package web

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

func (Resolver) Methods() []did.Method {
	return []did.Method{did.WebMethod}
}

// Resolve fetches and returns the Document from the expected URL
// specification: https://w3c-ccg.github.io/did-method-web/#read-resolve
func (Resolver) Resolve(_ context.Context, id string, _ ...resolver.ResolutionOption) (*resolver.ResolutionResult, error) {
	if !strings.HasPrefix(id, WebPrefix) {
		return nil, fmt.Errorf("not a did:web DID: %s", id)
	}
	didWeb := DIDWeb(id)
	doc, err := didWeb.Resolve()
	if err != nil {
		return nil, errors.Wrapf(err, "cresolving did:web DID: %s", id)
	}
	return &resolver.ResolutionResult{Document: *doc}, nil
}
