package ion

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestCreateLongFormDID(t *testing.T) {
	recoveryKeyJSON, err := getTestData("jwkes256k1public.json")
	assert.NoError(t, err)
	var recoveryKey crypto.PublicKeyJWK
	err = json.Unmarshal([]byte(recoveryKeyJSON), &recoveryKey)
	assert.NoError(t, err)

	updateKeyJSON, err := getTestData("jwkes256k2public.json")
	assert.NoError(t, err)
	var updateKey crypto.PublicKeyJWK
	err = json.Unmarshal([]byte(updateKeyJSON), &updateKey)
	assert.NoError(t, err)

	publicKeyJSON, err := getTestData("publickeymodel1.json")
	assert.NoError(t, err)
	var publicKey PublicKey
	err = json.Unmarshal([]byte(publicKeyJSON), &publicKey)
	assert.NoError(t, err)

	serviceJSON, err := getTestData("service1.json")
	assert.NoError(t, err)
	var service Service
	err = json.Unmarshal([]byte(serviceJSON), &service)
	assert.NoError(t, err)

	document := Document{
		PublicKeys: []PublicKey{
			publicKey,
		},
		Services: []Service{
			service,
		},
	}

	longFormDID, err := CreateLongFormDID(recoveryKey, updateKey, document)
	assert.NoError(t, err)
	assert.NotEmpty(t, longFormDID)

	expectedLongFormDID := "did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ"
	assert.Equal(t, expectedLongFormDID, longFormDID)

	expectedDID, expectedIS, err := DecodeLongFormDID(expectedLongFormDID)
	assert.NoError(t, err)

	ourDID, ourInitialState, ourErr := DecodeLongFormDID(longFormDID)
	assert.NoError(t, ourErr)

	assert.Equal(t, expectedDID, ourDID)
	assert.Equal(t, expectedIS, ourInitialState)
}
