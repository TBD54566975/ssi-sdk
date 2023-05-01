package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDilithiumSignVerify(t *testing.T) {
	t.Run("Able to generate dilithium key pairs for each mode", func(tt *testing.T) {
		tests := []struct {
			m       DilithiumMode
			wantErr bool
		}{
			{
				Dilithium2,
				false,
			},
			{
				Dilithium3,
				false,
			},
			{
				Dilithium5,
				false,
			},
			{
				"invalid",
				true,
			},
		}
		for _, test := range tests {
			tt.Run(test.m.String(), func(ttt *testing.T) {
				pk, sk, err := GenerateDilithiumKeyPair(test.m)
				if test.wantErr {
					assert.Error(ttt, err)
					assert.Nil(ttt, pk)
					assert.Nil(ttt, sk)
				} else {
					assert.NoError(ttt, err)
					assert.NotNil(ttt, pk)
					assert.NotNil(ttt, sk)
				}
			})
		}
	})

	t.Run("Able to sign and verify data with each mode of Dilithium keys", func(tt *testing.T) {
		tests := []struct {
			m DilithiumMode
		}{
			{
				Dilithium2,
			},
			{
				Dilithium3,
			},
			{
				Dilithium5,
			},
		}
		for _, test := range tests {
			tt.Run(test.m.String(), func(ttt *testing.T) {
				_, sk, err := GenerateDilithiumKeyPair(test.m)
				assert.NoError(ttt, err)

				signer, err := NewDilithiumSigner("test-KID", sk)
				assert.NoError(ttt, err)
				assert.NotEmpty(ttt, signer)

				verifier, err := NewDilithiumVerifier("test-KID", signer.PublicKey)
				assert.NoError(ttt, err)
				assert.NotEmpty(ttt, verifier)

				msg := []byte("test message")
				sig := signer.Sign(msg)
				assert.NotEmpty(ttt, sig)

				verified := verifier.Verify(msg, sig)
				assert.True(ttt, verified)
			})
		}
	})

	t.Run("Able to extract the mode for each Dilithium private key type", func(tt *testing.T) {
		tests := []struct {
			m DilithiumMode
		}{
			{
				Dilithium2,
			},
			{
				Dilithium3,
			},
			{
				Dilithium5,
			},
		}
		for _, test := range tests {
			tt.Run(test.m.String(), func(ttt *testing.T) {
				_, privKey, err := GenerateDilithiumKeyPair(test.m)
				assert.NoError(tt, err)

				mode, err := GetModeFromDilithiumPrivateKey(privKey)
				assert.NoError(tt, err)
				assert.Equal(tt, test.m, mode)
			})
		}
	})

	t.Run("Able to extract the mode for each Dilithium public key type", func(tt *testing.T) {
		tests := []struct {
			m DilithiumMode
		}{
			{
				Dilithium2,
			},
			{
				Dilithium3,
			},
			{
				Dilithium5,
			},
		}
		for _, test := range tests {
			tt.Run(test.m.String(), func(ttt *testing.T) {
				pubKey, _, err := GenerateDilithiumKeyPair(test.m)
				assert.NoError(tt, err)

				mode, err := GetModeFromDilithiumPublicKey(pubKey)
				assert.NoError(tt, err)
				assert.Equal(tt, test.m, mode)
			})
		}
	})
}
