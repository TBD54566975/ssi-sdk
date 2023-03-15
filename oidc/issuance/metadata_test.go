package issuance

import (
	_ "embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/require"
)

//go:embed example_issuer_metadata.json
var exampleIssuerMetadata []byte

func TestUnmarshalAndMarshallIsLossless(t *testing.T) {
	var m IssuerMetadata
	require.NoError(t, json.Unmarshal(exampleIssuerMetadata, &m))

	jsonData, err := json.Marshal(m)
	require.NoError(t, err)
	require.JSONEq(t, string(exampleIssuerMetadata), string(jsonData))
}

func TestInvalidJSON(t *testing.T) {
	claimWithManyLocales := []byte(`{
	  "display": [
		{
		  "name": "Given Name",
		  "locale": "en-US"
		},
		{
		  "name": "Given Name 2",
		  "locale": "en-US"
		}
	  ]
	}`)
	err := json.Unmarshal(claimWithManyLocales, &Claim{})
	require.Error(t, err)
	require.Equal(t, "found repeated claim.display.locale for en-US", err.Error())
}
