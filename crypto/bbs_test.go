package crypto

import (
	"encoding/base64"
	"testing"

	bbs "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateBBSKeyPair(t *testing.T) {
	t.Run("generate key pair", func(tt *testing.T) {
		pubKey, privKey, err := GenerateBBSKeyPair()
		assert.NotEmpty(tt, pubKey)
		assert.NotEmpty(tt, privKey)
		assert.NoError(tt, err)
	})

	t.Run("sign and verify message", func(tt *testing.T) {
		pubKey, privKey, err := GenerateBBSKeyPair()
		assert.NoError(tt, err)

		msg := []byte("hello world")
		signature, err := SignBBSMessage(privKey, msg)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signature)

		err = VerifyBBSMessage(pubKey, signature, msg)
		assert.NoError(tt, err)
	})

	// This test aims to verify implementation compatibility with the aries-framework-go, taken from here:
	// https://github.com/hyperledger/aries-framework-go/blob/02f80847168a99c8eb3baeaafcba8d0367bd9551/pkg/doc/signature/verifier/public_key_verifier_test.go#L452
	t.Run("verify test vector", func(tt *testing.T) {
		// pkBase58 from did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2
		pubKeyBase58 := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
		pubKeyBytes, err := base58.Decode(pubKeyBase58)
		assert.NoError(tt, err)

		bbsPubKey, err := bbs.UnmarshalPublicKey(pubKeyBytes)
		assert.NoError(tt, err)

		signatureB64 := `qPrB+1BLsVSeOo1ci8dMF+iR6aa5Q6iwV/VzXo2dw94ctgnQGxaUgwb8Hd68IiYTVabQXR+ZPuwJA//GOv1OwXRHkHqXg9xPsl8HcaXaoWERanxYClgHCfy4j76Vudr14U5AhT3v8k8f0oZD+zBIUQ==`
		signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
		require.NoError(tt, err)

		// Case 16 (https://github.com/w3c-ccg/vc-http-api/pull/128)
		msg := `
_:c14n0 <http://purl.org/dc/terms/created> "2021-02-23T19:31:12Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#BbsBlsSignature2020> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2#zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2> .
<did:example:b34ca6cd37bbf23> <http://schema.org/birthDate> "1958-07-17"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<did:example:b34ca6cd37bbf23> <http://schema.org/familyName> "SMITH" .
<did:example:b34ca6cd37bbf23> <http://schema.org/gender> "Male" .
<did:example:b34ca6cd37bbf23> <http://schema.org/givenName> "JOHN" .
<did:example:b34ca6cd37bbf23> <http://schema.org/image> <data:image/png;base64,iVBORw0KGgo...kJggg==> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://schema.org/Person> .
<did:example:b34ca6cd37bbf23> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResident> .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#birthCountry> "Bahamas" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#commuterClassification> "C1" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprCategory> "C09" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#lprNumber> "999-999-999" .
<did:example:b34ca6cd37bbf23> <https://w3id.org/citizenship#residentSince> "2015-01-01"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/description> "Government of Example Permanent Resident Card." .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://schema.org/name> "Permanent Resident Card" .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/citizenship#PermanentResidentCard> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:b34ca6cd37bbf23> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#expirationDate> "2029-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuanceDate> "2019-12-03T12:19:52Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://issuer.oidp.uscis.gov/credentials/83627465> <https://www.w3.org/2018/credentials#issuer> <did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2> .
`
		err = VerifyBBSMessage(bbsPubKey, signatureBytes, []byte(msg))
		assert.NoError(tt, err)
	})
}

func TestBBSSignatureEncoding(t *testing.T) {
	pubKey, privKey, err := GenerateBBSKeyPair()
	assert.NotNil(t, pubKey)
	assert.NotNil(t, privKey)
	assert.NoError(t, err)

	signature, err := SignBBSMessage(privKey, []byte("hello world"))
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	encoded := base64.RawStdEncoding.EncodeToString(signature)
	assert.NotEmpty(t, encoded)

	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	assert.NoError(t, err)
	assert.NotEmpty(t, decoded)

	assert.Equal(t, signature, decoded)

	err = VerifyBBSMessage(pubKey, decoded, []byte("hello world"))
	assert.NoError(t, err)
}
