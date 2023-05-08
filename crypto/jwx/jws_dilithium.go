package jwx

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

const (
	DilithiumMode2Alg jwa.SignatureAlgorithm = "CRYDI2"
	DilithiumMode3Alg jwa.SignatureAlgorithm = "CRYDI3"
	DilithiumMode5Alg jwa.SignatureAlgorithm = "CRYDI5"
)

// DilithiumSignerVerifier implements the jws.Signer and jws.Verifier interfaces for use with the jwx library
type DilithiumSignerVerifier struct {
	m dilithium.Mode
}

// NewDilithiumMode2Signer returns a new DilithiumSignerVerifier configured for Dilithium Mode 2
func NewDilithiumMode2Signer() (jws.Signer, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode2}, nil
}

// NewDilithiumMode2Verifier returns a new DilithiumSignerVerifier configured for Dilithium Mode 2
func NewDilithiumMode2Verifier() (jws.Verifier, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode2}, nil
}

// NewDilithiumMode3Signer returns a new DilithiumSignerVerifier configured for Dilithium Mode 3
func NewDilithiumMode3Signer() (jws.Signer, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode3}, nil
}

// NewDilithiumMode3Verifier returns a new DilithiumSignerVerifier configured for Dilithium Mode 3
func NewDilithiumMode3Verifier() (jws.Verifier, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode3}, nil
}

// NewDilithiumMode5Signer returns a new DilithiumSignerVerifier configured for Dilithium Mode 5
func NewDilithiumMode5Signer() (jws.Signer, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode5}, nil
}

// NewDilithiumMode5Verifier returns a new DilithiumSignerVerifier configured for Dilithium Mode 5
func NewDilithiumMode5Verifier() (jws.Verifier, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode5}, nil
}

// Algorithm returns the jwa.SignatureAlgorithm value for the configured Dilithium mode
func (s DilithiumSignerVerifier) Algorithm() jwa.SignatureAlgorithm {
	switch s.m {
	case dilithium.Mode2:
		return DilithiumMode2Alg
	case dilithium.Mode3:
		return DilithiumMode3Alg
	case dilithium.Mode5:
		return DilithiumMode5Alg
	default:
		return ""
	}
}

// Sign signs the payload using the provided key
func (s DilithiumSignerVerifier) Sign(payload []byte, keyif any) ([]byte, error) {
	switch key := keyif.(type) {
	case dilithium.PrivateKey:
		return s.m.Sign(key, payload), nil
	default:
		return nil, fmt.Errorf(`invalid key type %T`, keyif)
	}
}

// Verify verifies the signature against the payload using the provided key
func (s DilithiumSignerVerifier) Verify(payload []byte, signature []byte, keyif any) error {
	switch key := keyif.(type) {
	case dilithium.PublicKey:
		if s.m.Verify(key, payload, signature) {
			return nil
		}
		return fmt.Errorf(`failed to verify dilithium signature`)
	default:
		return fmt.Errorf(`invalid key type %T`, keyif)
	}
}
