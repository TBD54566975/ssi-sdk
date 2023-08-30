package schema

import (
	"context"
	"fmt"
	"net/http"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

type VCJSONSchemaAccess interface {
	// GetVCJSONSchema returns a vc json schema for the given ID as a json string according to the given VCJSONSchemaType
	GetVCJSONSchema(ctx context.Context, t VCJSONSchemaType, id string) (VCJSONSchema, error)
}

// RemoteAccess is used to retrieve a vc json schema from a remote location
type RemoteAccess struct {
	baseURL *string
	*http.Client
}

// NewRemoteAccess returns a new instance of RemoteAccess, accepting an optional baseURL
// to prepend to any schema id that is being fetched.
func NewRemoteAccess(baseURL *string) *RemoteAccess {
	return &RemoteAccess{
		baseURL: baseURL,
		Client:  http.DefaultClient,
	}
}

// GetVCJSONSchema returns a vc json schema for the given ID and its type as a json string by making a GET request
// to the given ID. If a baseURL was provided to NewRemoteAccess, it will be prepended to the ID.
func (ra *RemoteAccess) GetVCJSONSchema(ctx context.Context, t VCJSONSchemaType, id string) (VCJSONSchema, error) {
	if !IsSupportedVCJSONSchemaType(t.String()) {
		return nil, fmt.Errorf("credential schema type<%T> is not supported", t)
	}
	url := id
	if ra.baseURL != nil {
		url = *ra.baseURL + id
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}
	resp, err := ra.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "getting schema")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("getting schema, status code: %d", resp.StatusCode)
	}

	var schema VCJSONSchema
	if err = json.NewDecoder(resp.Body).Decode(&schema); err != nil {
		return nil, errors.Wrap(err, "decoding schema")
	}
	return schema, nil
}
