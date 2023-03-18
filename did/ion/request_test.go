package ion

import (
	"embed"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

var (
	//go:embed testdata
	testData embed.FS
)

// https://github.com/decentralized-identity/ion-sdk/blob/main/tests/IonRequest.spec.ts#L7
func TestCreateRequest(t *testing.T) {
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
		PublicKeys: []PublicKey{publicKey},
		Services:   []Service{service},
	}

	createRequest, err := NewCreateRequest(recoveryKey, updateKey, document)
	assert.NoError(t, err)
	assert.NotEmpty(t, createRequest)

	assert.Equal(t, Create, createRequest.Type)
	assert.Equal(t, "EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA", createRequest.Delta.UpdateCommitment)
	assert.Len(t, createRequest.Delta.Patches, 1)
	assert.Equal(t, "EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA", createRequest.SuffixData.RecoveryCommitment)
	assert.Equal(t, "EiCfDWRnYlcD9EGA3d_5Z1AHu-iYqMbJ9nfiqdz5S8VDbg", createRequest.SuffixData.DeltaHash)
}

func TestUpdateRequest(t *testing.T) {
	updateKeyJSON, err := getTestData("jwkes256k1public.json")
	assert.NoError(t, err)
	var updateKey crypto.PublicKeyJWK
	err = json.Unmarshal([]byte(updateKeyJSON), &updateKey)
	assert.NoError(t, err)

	updatePrivateKeyJSON, err := getTestData("jwkes256k1private.json")
	assert.NoError(t, err)
	var updatePrivateKey crypto.PrivateKeyJWK
	err = json.Unmarshal([]byte(updatePrivateKeyJSON), &updatePrivateKey)
	assert.NoError(t, err)

	nextUpdateKeyJSON, err := getTestData("jwkes256k2public.json")
	assert.NoError(t, err)
	var nextUpdateKey crypto.PublicKeyJWK
	err = json.Unmarshal([]byte(nextUpdateKeyJSON), &nextUpdateKey)
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

	signer, err := crypto.NewJWTSignerFromJWK("", updatePrivateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, signer)

	didSuffix := "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"
	stateChange := StateChange{
		ServicesToAdd:        []Service{service},
		ServiceIDsToRemove:   []string{"someId1"},
		PublicKeysToAdd:      []PublicKey{publicKey},
		PublicKeyIDsToRemove: []string{"someId2"},
	}
	updateRequest, err := NewUpdateRequest(didSuffix, updateKey, nextUpdateKey, *signer, stateChange)
	assert.NoError(t, err)
	assert.NotEmpty(t, updateRequest)

	assert.Equal(t, didSuffix, updateRequest.DIDSuffix)
	assert.Equal(t, Update, updateRequest.Type)
	assert.Equal(t, "EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ", updateRequest.RevealValue)
	assert.Equal(t, "eyJhbGciOiJFUzI1NksifQ.eyJ1cGRhdGVLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sImRlbHRhSGFzaCI6IkVpQXZsbVVRYy1jaDg0Slp5bmdQdkJzUkc3eWh4aUFSenlYOE5lNFQ4LTlyTncifQ.Q9MuoQqFlhYhuLDgx4f-0UM9QyCfZp_cXt7vnQ4ict5P4_ZWKwG4OXxxqFvdzE-e3ZkEbvfR0YxEIpYO9MrPFw", updateRequest.SignedData)
	assert.Equal(t, "EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA", updateRequest.Delta.UpdateCommitment)
	assert.Len(t, updateRequest.Delta.Patches, 4)
}

func TestRecoverRequest(t *testing.T) {

}

func TestDeactivateRequest(t *testing.T) {

}

func getTestData(fileName string) (string, error) {
	b, err := testData.ReadFile("testdata/" + fileName)
	return string(b), err
}
