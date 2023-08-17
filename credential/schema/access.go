package schema

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/credential/parsing"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

type VCJSONSchemaAccess interface {
	// GetVCJSONSchema returns a vc json schema for the given ID as a json string according to the given VCJSONSchemaType
	GetVCJSONSchema(ctx context.Context, t VCJSONSchemaType, id string) (JSONSchema, error)
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
func (ra *RemoteAccess) GetVCJSONSchema(ctx context.Context, t VCJSONSchemaType, id string) (JSONSchema, error) {
	if !IsSupportedVCJSONSchemaType(t.String()) {
		return nil, fmt.Errorf("credential schema type<%T> is not supported", t)
	}
	url := id
	if ra.baseURL != nil {
		url = *ra.baseURL + id
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error creating request")
	}
	resp, err := ra.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error getting schema")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("error getting schema, status code: %d", resp.StatusCode)
	}

	switch t {
	case JsonSchemaCredentialType:
		// either a jwt or credential json
		var schemaCred any
		if err = json.NewDecoder(resp.Body).Decode(&schemaCred); err != nil {
			return nil, errors.Wrap(err, "error decoding schema to generic response")
		}
		_, _, cred, err := parsing.ToCredential(schemaCred)
		if err != nil {
			return nil, errors.Wrap(err, "error decoding schema from credential")
		}
		jsonSchemaValue := cred.CredentialSubject.GetJSONSchema()
		credSubjectBytes, err := json.Marshal(jsonSchemaValue)
		if err != nil {
			return nil, errors.Wrap(err, "error marshalling jsonSchema property in the credential subject")
		}
		var schema JSONSchema
		if err = json.Unmarshal(credSubjectBytes, &schema); err != nil {
			return nil, errors.Wrap(err, "error unmarshalling credential subject to schema")
		}
		return schema, nil
	case JSONSchemaType:
		var schema JSONSchema
		if err = json.NewDecoder(resp.Body).Decode(&schema); err != nil {
			return nil, errors.Wrap(err, "error decoding schema")
		}
		return schema, nil
	}
	return nil, errors.New("unexpected error getting vc json schema")
}
