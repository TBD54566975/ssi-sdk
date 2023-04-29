package jwx

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
)

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

			const payload = "Lorem Ipsum"
			signed, err := jws.Sign([]byte(payload), jws.WithKey(test.alg, privKey))
			assert.NoError(tt, err)

			verified, err := jws.Verify(signed, jws.WithKey(test.alg, pubKey))
			assert.NoError(tt, err)

			assert.Equal(tt, string(verified), payload)
		})
	}
}
