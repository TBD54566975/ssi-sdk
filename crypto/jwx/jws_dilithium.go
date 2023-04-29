package jwx

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func init() {
	jws.RegisterSigner(DilithiumMode2Alg, jws.SignerFactoryFn(NewDilithiumMode2Signer))
	jws.RegisterVerifier(DilithiumMode2Alg, jws.VerifierFactoryFn(NewDilithiumMode2Verifier))
	jws.RegisterSigner(DilithiumMode3Alg, jws.SignerFactoryFn(NewDilithiumMode3Signer))
	jws.RegisterVerifier(DilithiumMode3Alg, jws.VerifierFactoryFn(NewDilithiumMode3Verifier))
	jws.RegisterSigner(DilithiumMode5Alg, jws.SignerFactoryFn(NewDilithiumMode5Signer))
	jws.RegisterVerifier(DilithiumMode5Alg, jws.VerifierFactoryFn(NewDilithiumMode5Verifier))
}

const (
	DilithiumMode2Alg jwa.SignatureAlgorithm = "CRYDI2"
	DilithiumMode3Alg jwa.SignatureAlgorithm = "CRYDI3"
	DilithiumMode5Alg jwa.SignatureAlgorithm = "CRYDI5"
)

type DilithiumSignerVerifier struct {
	m dilithium.Mode
}

func NewDilithiumMode2Signer() (jws.Signer, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode2}, nil
}

func NewDilithiumMode2Verifier() (jws.Verifier, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode2}, nil
}

func NewDilithiumMode3Signer() (jws.Signer, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode3}, nil
}

func NewDilithiumMode3Verifier() (jws.Verifier, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode3}, nil
}

func NewDilithiumMode5Signer() (jws.Signer, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode5}, nil
}

func NewDilithiumMode5Verifier() (jws.Verifier, error) {
	return &DilithiumSignerVerifier{m: dilithium.Mode5}, nil
}

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

func (s DilithiumSignerVerifier) Sign(payload []byte, keyif interface{}) ([]byte, error) {
	switch key := keyif.(type) {
	case dilithium.PrivateKey:
		return s.m.Sign(key, payload), nil
	default:
		return nil, fmt.Errorf(`invalid key type %T`, keyif)
	}
}

func (s DilithiumSignerVerifier) Verify(payload []byte, signature []byte, keyif interface{}) error {
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
