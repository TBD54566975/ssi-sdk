package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDilithiumSignVerify(t *testing.T) {
	t.Run("Generate all possible keys per mode", func(tt *testing.T) {
		pk, sk, err := GenerateDilithiumKeyPair(Dilithium2)
		assert.NoError(tt, err)
		assert.NotNil(tt, pk)
		assert.NotNil(tt, sk)

		pk, sk, err = GenerateDilithiumKeyPair(Dilithium3)
		assert.NoError(tt, err)
		assert.NotNil(tt, pk)
		assert.NotNil(tt, sk)

		pk, sk, err = GenerateDilithiumKeyPair(Dilithium5)
		assert.NoError(tt, err)
		assert.NotNil(tt, pk)
		assert.NotNil(tt, sk)

		_, _, err = GenerateDilithiumKeyPair("unsupported")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported dilithium mode")
	})

	t.Run("mismatched mode for signer", func(tt *testing.T) {
		_, sk, err := GenerateDilithiumKeyPair(Dilithium2)
		assert.NoError(tt, err)
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("The code did not panic")
			}
		}()
		_, _ = NewDilithiumSigner("test-kid", Dilithium5, sk)
	})

	t.Run("mismatched mode for verifier", func(tt *testing.T) {
		_, sk, err := GenerateDilithiumKeyPair(Dilithium2)
		assert.NoError(tt, err)
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("The code did not panic")
			}
		}()
		_, _ = NewDilithiumVerifier("test-kid", Dilithium5, sk)
	})

	t.Run("sign and verify", func(tt *testing.T) {
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

				signer, err := NewDilithiumSigner("test-kid", test.m, sk)
				assert.NoError(ttt, err)
				assert.NotEmpty(ttt, signer)

				verifier, err := NewDilithiumVerifier("test-kid", test.m, signer.PublicKey)
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

	t.Run("get mode from private key", func(tt *testing.T) {
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

	t.Run("get mode from public key", func(tt *testing.T) {
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
