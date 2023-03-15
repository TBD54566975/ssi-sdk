package issuance

import (
	_ "embed"
	"testing"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
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

func TestInvalidClaimJSON(t *testing.T) {
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

func TestInvalidIssuerMetadataJSON(t *testing.T) {
	metadataWithManyCredentialSupportedIDs := []byte(`{
		"credentials_supported": [{
				"id":"one"
			},
			{
				"id":"one"
			}
		]
	}`)

	err := json.Unmarshal(metadataWithManyCredentialSupportedIDs, &IssuerMetadata{})

	require.Error(t, err)
	require.Equal(t, "found repeated credentials_supported.id for one", err.Error())
}

func TestDIDBindingMethods(t *testing.T) {
	var c CredentialSupported
	credentialSupportedJSON := []byte(`{
      "cryptographic_binding_methods_supported": [
        "did:web",
        "did:ion",
        "did",
        "jwk"
      ]
    }`)
	require.NoError(t, json.Unmarshal(credentialSupportedJSON, &c))

	assert.ElementsMatch(t, []did.Method{"web", "ion"}, c.BindingDIDMethods())
}
