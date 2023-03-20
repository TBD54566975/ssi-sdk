package ion

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
)

// https://github.com/decentralized-identity/ion-sdk/blob/main/tests/IonRequest.spec.ts#L7
func TestCreateRequest(t *testing.T) {
	var recoveryKey crypto.PublicKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k1public.json", &recoveryKey)

	var updateKey crypto.PublicKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k2public.json", &updateKey)

	var publicKey PublicKey
	RetrieveTestVectorAs(t, "publickeymodel1.json", &publicKey)

	var service Service
	RetrieveTestVectorAs(t, "service1.json", &service)

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

// https://github.com/decentralized-identity/ion-sdk/blob/main/tests/IonRequest.spec.ts#L32
func TestUpdateRequest(t *testing.T) {
	var updateKey crypto.PublicKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k1public.json", &updateKey)

	var updatePrivateKey crypto.PrivateKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k1private.json", &updatePrivateKey)

	var nextUpdateKey crypto.PublicKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k2public.json", &nextUpdateKey)

	var publicKey PublicKey
	RetrieveTestVectorAs(t, "publickeymodel1.json", &publicKey)

	var service Service
	RetrieveTestVectorAs(t, "service1.json", &service)

	signer, err := NewBTCSignerVerifier(updatePrivateKey)
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

// https://github.com/decentralized-identity/ion-sdk/blob/main/tests/IonRequest.spec.ts#L72
func TestRecoverRequest(t *testing.T) {
	var publicKey PublicKey
	RetrieveTestVectorAs(t, "publickeymodel1.json", &publicKey)

	var service Service
	RetrieveTestVectorAs(t, "service1.json", &service)

	document := Document{PublicKeys: []PublicKey{publicKey}, Services: []Service{service}}

	var recoveryKey crypto.PublicKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k1public.json", &recoveryKey)

	var recoveryPrivateKey crypto.PrivateKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k1private.json", &recoveryPrivateKey)

	var nextRecoveryKey crypto.PublicKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k2public.json", &nextRecoveryKey)

	var nextUpdateKey crypto.PublicKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k3public.json", &nextUpdateKey)

	signer, err := NewBTCSignerVerifier(recoveryPrivateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, signer)

	didSuffix := "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"
	recoverRequest, err := NewRecoverRequest(didSuffix, recoveryKey, nextRecoveryKey, nextUpdateKey, document, *signer)
	assert.NoError(t, err)
	assert.NotEmpty(t, recoverRequest)

	assert.Equal(t, didSuffix, recoverRequest.DIDSuffix)
	assert.Equal(t, "EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ", recoverRequest.RevealValue)
	assert.Equal(t, Recover, recoverRequest.Type)
	assert.Equal(t, recoverRequest.SignedData, "eyJhbGciOiJFUzI1NksifQ.eyJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaURLSWt3cU82OUlQRzNwT2xIa2RiODZuWXQwYU54U0hadTJyLWJoRXpuamRBIiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sImRlbHRhSGFzaCI6IkVpQm9HNlFtamlTSm5ON2phaldnaV9vZDhjR3dYSm9Nc2RlWGlWWTc3NXZ2SkEifQ.58n6Fel9DmRAXxwcJMUwYaUhmj5kigKMNrGjr7eJaJcjOmjvwlKLSjiovWiYrb9yjkfMAjpgbAdU_2EDI1_lZw")
	assert.Equal(t, "EiBJGXo0XUiqZQy0r-fQUHKS3RRVXw5nwUpqGVXEGuTs-g", recoverRequest.Delta.UpdateCommitment)
	assert.Len(t, recoverRequest.Delta.Patches, 1)
}

// https://github.com/decentralized-identity/ion-sdk/blob/main/tests/IonRequest.spec.ts#L102
func TestDeactivateRequest(t *testing.T) {
	var recoveryKey crypto.PublicKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k1public.json", &recoveryKey)

	var recoveryPrivateKey crypto.PrivateKeyJWK
	RetrieveTestVectorAs(t, "jwkes256k1private.json", &recoveryPrivateKey)

	signer, err := NewBTCSignerVerifier(recoveryPrivateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, signer)

	didSuffix := "EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg"
	deactivateRequest, err := NewDeactivateRequest(didSuffix, recoveryKey, *signer)
	assert.NoError(t, err)
	assert.NotEmpty(t, deactivateRequest)

	assert.Equal(t, didSuffix, deactivateRequest.DIDSuffix)
	assert.Equal(t, Deactivate, deactivateRequest.Type)
	assert.Equal(t, deactivateRequest.RevealValue, "EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ")
	assert.Equal(t, deactivateRequest.SignedData, "eyJhbGciOiJFUzI1NksifQ.eyJkaWRTdWZmaXgiOiJFaUR5T1FiYlpBYTNhaVJ6ZUNrVjdMT3gzU0VSampIOTNFWG9JTTNVb040b1dnIiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn19.uLgnDBmmFzST4VTmdJcmFKVicF0kQaBqEnRQLbqJydgIg_2oreihCA5sBBIUBlSXwvnA9xdK97ksJGmPQ7asPQ")
}
