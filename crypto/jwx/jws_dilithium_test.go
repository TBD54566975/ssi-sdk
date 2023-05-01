package jwx

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
)

// Registers the Dilithium Signers and Verifiers with the jwx library
func init() {
	jws.RegisterSigner(DilithiumMode2Alg, jws.SignerFactoryFn(NewDilithiumMode2Signer))
	jws.RegisterVerifier(DilithiumMode2Alg, jws.VerifierFactoryFn(NewDilithiumMode2Verifier))
	jws.RegisterSigner(DilithiumMode3Alg, jws.SignerFactoryFn(NewDilithiumMode3Signer))
	jws.RegisterVerifier(DilithiumMode3Alg, jws.VerifierFactoryFn(NewDilithiumMode3Verifier))
	jws.RegisterSigner(DilithiumMode5Alg, jws.SignerFactoryFn(NewDilithiumMode5Signer))
	jws.RegisterVerifier(DilithiumMode5Alg, jws.VerifierFactoryFn(NewDilithiumMode5Verifier))
}

func TestJWSDilithium(t *testing.T) {
	tests := []struct {
		m   crypto.DilithiumMode
		alg jwa.SignatureAlgorithm
	}{
		{
			m:   crypto.Dilithium2,
			alg: DilithiumMode2Alg,
		},
		{
			m:   crypto.Dilithium3,
			alg: DilithiumMode3Alg,
		},
		{
			m:   crypto.Dilithium5,
			alg: DilithiumMode5Alg,
		},
	}
	for _, test := range tests {
		t.Run(test.m.String(), func(tt *testing.T) {
			pubKey, privKey, err := crypto.GenerateDilithiumKeyPair(test.m)
			assert.NoError(tt, err)

			mode, err := crypto.GetModeFromDilithiumPublicKey(pubKey)
			assert.NoError(tt, err)
			assert.Equal(tt, test.m, mode)

			const payload = "here's johnny!"
			signed, err := jws.Sign([]byte(payload), jws.WithKey(test.alg, privKey))
			assert.NoError(tt, err)

			verified, err := jws.Verify(signed, jws.WithKey(test.alg, pubKey))
			assert.NoError(tt, err)

			assert.Equal(tt, string(verified), payload)
		})
	}
}

// https://www.ietf.org/id/draft-ietf-cose-dilithium-00.html#section-6.1.1.3
func TestJWSDilithiumVector(t *testing.T) {
	t.Skip("skipping until the upstream test vectors are updated")

	t.Run("Verify Test Vector JWS", func(tt *testing.T) {
		var privKeyJWK PrivateKeyJWK
		retrieveTestVectorAs(tt, dilithiumPrivateJWK, &privKeyJWK)
		assert.NotEmpty(tt, privKeyJWK)

		pubKey, err := privKeyJWK.ToPublicKeyJWK().ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKey)

		mode, err := crypto.GetModeFromDilithiumPublicKey(pubKey.(dilithium.PublicKey))
		assert.NoError(tt, err)
		assert.Equal(tt, crypto.Dilithium5, mode)

		var testVectorJWS struct {
			JWS string `json:"jws"`
		}
		retrieveTestVectorAs(tt, dilithiumJWS, &testVectorJWS)
		assert.NotEmpty(tt, testVectorJWS)
		verified, err := jws.Verify([]byte(testVectorJWS.JWS), jws.WithKey(DilithiumMode5Alg, pubKey))
		assert.NoError(tt, err)

		assert.Equal(tt, string(verified), "woo")
	})
}
