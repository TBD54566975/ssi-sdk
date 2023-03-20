package ion

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestBTCSignerVerifier(t *testing.T) {
	privateKeyJWKJSON, err := getTestData("jwkes256k1private.json")
	assert.NoError(t, err)
	var privateKeyJWK crypto.PrivateKeyJWK
	err = json.Unmarshal([]byte(privateKeyJWKJSON), &privateKeyJWK)
	assert.NoError(t, err)

	signer, err := NewBTCSignerVerifier(privateKeyJWK)
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	t.Run("Sign and verify", func(tt *testing.T) {
		msg := "test"
		msgHash := Hash([]byte(msg))
		signature, err := signer.Sign(msgHash)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signature)

		verified, err := signer.Verify(msgHash, signature)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})

	t.Run("Sign and verify JWS", func(tt *testing.T) {
		jwt, err := signer.SignJWT(map[string]any{"test": "data"})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwt)

		verified, err := signer.VerifyJWS(jwt)
		assert.NoError(tt, err)
		assert.True(tt, verified)
	})
}

func TestCrap(t *testing.T) {
	privateKeyHex := "2b91616e20be36804b8b40848e93fa312e9d736d8cdfa28826b3cca1ceff7e97"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	assert.NoError(t, err)

	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)

	signingContentHex := "65794a68624763694f694a46557a49314e6b736966512e65794a31634752686447564c5a586b694f6e736961335235496a6f6952554d694c434a6a636e59694f694a7a5a574e774d6a5532617a45694c434a34496a6f69626b6c7862464a446544426c65554a5457474e52626e464563464a6c55335930656e565861486444556c647a6332396a4f557866626d6f3251534973496e6b694f694a70527a4935566b733262444a564e584e4c516c70565530706c55485a35526e567a57476454624573795a4552476246646851303034526a6472496e3073496d526c624852685347467a61434936496b567051585a73625656525979316a61446730536c7035626d6451646b4a7a556b63336557683461554653656e6c594f45356c4e4651344c546c79546e63696651"
	signingContentBytes, err := hex.DecodeString(signingContentHex)
	assert.NoError(t, err)

	hashedMessage := Hash(signingContentBytes)

	// same up to here

	signature, err := sign(privateKey, hashedMessage)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	encodedSignature := Encode(signature)
	assert.Equal(t, "Q9MuoQqFlhYhuLDgx4f-0UM9QyCfZp_cXt7vnQ4ict5P4_ZWKwG4OXxxqFvdzE-e3ZkEbvfR0YxEIpYO9MrPFw", encodedSignature)
}

func sign(privateKey *btcec.PrivateKey, dataHash []byte) ([]byte, error) {
	signature, err := ecdsa.SignCompact(privateKey, dataHash, false)
	if err != nil {
		return nil, err
	}

	rBytes := signature[1:33]
	sBytes := signature[33:65]

	// Convert the signature from DER format to 64-byte hexadecimal format
	r := fmt.Sprintf("%064s", hex.EncodeToString(rBytes))
	s := fmt.Sprintf("%064s", hex.EncodeToString(sBytes))

	// convert to bytes and return
	return hex.DecodeString(r + s)
}
