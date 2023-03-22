package ion

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

type (
	DIDION string
)

const (
	IONPrefix = "did:ion"
)

// IsValid checks if the did:ion is valid by checking for a valid prefix
// full validation is impossible without resolution
func (d DIDION) IsValid() bool {
	split := strings.Split(d.String(), IONPrefix+":")
	return len(split) == 2
}

func (d DIDION) String() string {
	return string(d)
}

func (d DIDION) Suffix() (string, error) {
	split := strings.Split(d.String(), IONPrefix+":")
	if len(split) != 2 {
		return "", errors.Wrap(util.InvalidFormatError, "did is malformed")
	}
	return split[1], nil
}

func (DIDION) Method() did.Method {
	return did.IONMethod
}

type Resolver struct {
	resolverURL string
}

func NewIONResolver(resolverURL string) (*Resolver, error) {
	if _, err := url.Parse(resolverURL); err != nil {
		return nil, errors.Wrap(err, "invalid resolver URL")
	}
	return &Resolver{resolverURL: resolverURL}, nil
}

func (i Resolver) Resolve(id string, _ did.ResolutionOptions) (*did.DIDResolutionResult, error) {
	if i.resolverURL == "" {
		return nil, errors.New("resolver URL is empty")
	}
	resp, err := http.Get(i.resolverURL + "/" + id)
	if err != nil {
		return nil, errors.Wrapf(err, "could not resolve with docURL %+v", i.resolverURL)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "could not resolve with response %+v", resp)
	}
	resolutionResult, err := did.ParseDIDResolution(body)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving did:ion DID: %s", id)
	}
	return resolutionResult, nil
}
