//go:build jwx_es256k

package exchange

import (
	"github.com/TBD54566975/did-sdk/util"
	"github.com/oliveagle/jsonpath"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConstructLimitedClaim(t *testing.T) {
	t.Run("Full Claim With Nesting", func(t *testing.T) {
		claim := getTestClaim()
		var limitedDescriptors []limitedInputDescriptor

		typePath := "$.type"
		typeValue, err := jsonpath.JsonPathLookup(claim, typePath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: typePath,
			Data: typeValue,
		})

		issuerPath := "$.issuer"
		issuerValue, err := jsonpath.JsonPathLookup(claim, issuerPath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: issuerPath,
			Data: issuerValue,
		})

		idPath := "$.credentialSubject.id"
		idValue, err := jsonpath.JsonPathLookup(claim, idPath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: idPath,
			Data: idValue,
		})

		namePath := "$.credentialSubject.firstName"
		nameValue, err := jsonpath.JsonPathLookup(claim, namePath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: namePath,
			Data: nameValue,
		})

		addressPath := "$.credentialSubject.address.*"
		addressValue, err := jsonpath.JsonPathLookup(claim, addressPath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: addressPath,
			Data: addressValue,
		})

		favoritesPath := "$.credentialSubject.favorites.citiesByState.CA"
		favoritesValue, err := jsonpath.JsonPathLookup(claim, favoritesPath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: favoritesPath,
			Data: favoritesValue,
		})

		result, err := constructLimitedClaim(limitedDescriptors)
		assert.NoError(t, err)
		assert.NotEmpty(t, result)
	})

	t.Run("Complex Path Parsing", func(t *testing.T) {
		claim := getTestClaim()
		var limitedDescriptors []limitedInputDescriptor

		filterPath := "$.credentialSubject.address[?(@.number > 0)]"
		filterValue, err := jsonpath.JsonPathLookup(claim, filterPath)
		assert.NoError(t, err)
		limitedDescriptors = append(limitedDescriptors, limitedInputDescriptor{
			Path: filterPath,
			Data: filterValue,
		})

		result, err := constructLimitedClaim(limitedDescriptors)
		assert.NoError(t, err)

		printerface(result)

		// make sure the result contains a value
		csValue, ok := result["credentialSubject"]
		assert.True(t, ok)
		assert.NotEmpty(t, csValue)

		addressValue, ok := csValue.(map[string]interface{})["address"]
		assert.True(t, ok)
		assert.NotEmpty(t, addressValue)
	})
}

func getTestClaim() map[string]interface{} {
	return map[string]interface{}{
		"@context": []interface{}{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		"type":         []string{"VerifiableCredential"},
		"issuer":       "did:example:123",
		"issuanceDate": "2021-01-01T19:23:24Z",
		"credentialSubject": map[string]interface{}{
			"id":        "did:example:abcd",
			"firstName": "Satoshi",
			"lastName":  "Nakamoto",
			"address": map[string]interface{}{
				"number":  1,
				"street":  "road street",
				"country": "USA",
			},
			"favorites": map[string]interface{}{
				"color": "blue",
				"citiesByState": map[string]interface{}{
					"NY": []string{"NY"},
					"CA": []string{"Oakland", "San Francisco"},
				},
			},
		},
	}
}

func printerface(d interface{}) {
	b, _ := util.PrettyJSON(d)
	println(string(b))
}