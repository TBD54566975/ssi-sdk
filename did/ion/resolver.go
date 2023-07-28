package ion

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Resolver struct {
	client  *http.Client
	baseURL url.URL
}

var _ resolution.Resolver = (*Resolver)(nil)

// NewIONResolver creates a new resolution for the ION DID method with a common base URL
// The base URL is the URL of the ION node, for example: https://ion.tbd.network
// The resolution will append the DID to the base URL to resolve the DID such as
//
//	https://ion.tbd.network/identifiers/did:ion:1234
//
// and similarly for submitting anchor operations to the ION node...
//
//	https://ion.tbd.network/operations
func NewIONResolver(client *http.Client, baseURL string) (*Resolver, error) {
	if client == nil {
		return nil, errors.New("client cannot be nil")
	}
	parsedURL, err := url.ParseRequestURI(baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "invalid resolution URL")
	}
	if parsedURL.Scheme != "https" {
		return nil, errors.New("invalid resolution URL scheme; must use https")
	}
	return &Resolver{
		client:  client,
		baseURL: *parsedURL,
	}, nil
}

// Resolve resolves a did:ion DID by appending the DID to the base URL with the identifiers path and making a GET request
func (i Resolver) Resolve(ctx context.Context, id string, _ ...resolution.Option) (*resolution.Result, error) {
	// first attempt to decode as a long form DID, if we get an error, continue
	if id == "" {
		return nil, errors.New("id cannot be empty")
	}
	if IsLongFormDID(id) {
		shortFormDID, initialState, err := DecodeLongFormDID(id)
		if err != nil {
			return nil, errors.Wrap(err, "invalid long form DID")
		}
		didDoc, err := PatchesToDIDDocument(shortFormDID, id, initialState.Delta.Patches)
		if err != nil {
			return nil, errors.Wrap(err, "reconstructing document from long form DID")
		}
		return &resolution.Result{
			Context:  "https://w3id.org/did-resolution/v1",
			Document: *didDoc,
			DocumentMetadata: &resolution.DocumentMetadata{
				EquivalentID: []string{shortFormDID},
				Method: resolution.Method{
					Published:          false,
					RecoveryCommitment: initialState.SuffixData.RecoveryCommitment,
					UpdateCommitment:   initialState.Delta.UpdateCommitment},
			}}, nil
	}

	if i.baseURL.String() == "" {
		return nil, errors.New("resolution URL cannot be empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.Join([]string{i.baseURL.String(), "identifiers", id}, "/"), nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving, with URL: %s", i.baseURL.String())
	}

	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving, with response %+v", resp)
	}
	if !is2xxStatusCode(resp.StatusCode) {
		return nil, fmt.Errorf("could not resolve DID: %q", string(body))
	}
	resolutionResult, err := resolution.ParseDIDResolution(body)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving did:ion DID<%s>", id)
	}
	return resolutionResult, nil
}

// Anchor submits an anchor operation to the ION node by appending the operations path to the base URL
// and making a POST request
func (i Resolver) Anchor(ctx context.Context, op AnchorOperation) (*resolution.Result, error) {
	if i.baseURL.String() == "" {
		return nil, errors.New("resolution URL cannot be empty")
	}
	jsonOpBytes, err := json.Marshal(op)
	if err != nil {
		return nil, errors.Wrapf(err, "marshalling anchor operation %+v", op)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.Join([]string{i.baseURL.String(), "operations"}, "/"), bytes.NewReader(jsonOpBytes))
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "posting anchor operation %+v", op)
	}

	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "could not resolve with response %+v", resp)
	}
	if !is2xxStatusCode(resp.StatusCode) {
		return nil, fmt.Errorf("anchor operation failed: %s", string(body))
	}
	logrus.Infof("successfully anchored operation: %s", string(body))

	var resolutionResult resolution.Result
	if err := json.Unmarshal(body, &resolutionResult); err != nil {
		return nil, errors.Wrap(err, "unmarshalling anchor response")
	}
	return &resolutionResult, nil
}

func (Resolver) Methods() []did.Method {
	return []did.Method{did.IONMethod}
}
