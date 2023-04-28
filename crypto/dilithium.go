package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/pkg/errors"
)

type (
	DilithiumMode string
)

func (m DilithiumMode) String() string {
	return string(m)
}

const (
	Dilithium2 DilithiumMode = "Dilithium2"
	Dilithium3 DilithiumMode = "Dilithium3"
	Dilithium5 DilithiumMode = "Dilithium5"
)

func GenerateDilithiumKeyPair(m DilithiumMode) (dilithium.PublicKey, dilithium.PrivateKey, error) {
	mode := dilithium.ModeByName(m.String())
	if mode == nil {
		return nil, nil, fmt.Errorf("unsupported dilithium mode: %s", m)
	}
	pk, sk, err := mode.GenerateKey(nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not generate key for dilithium")
	}
	return pk, sk, nil
}

type DilithiumSigner struct {
	kid  string
	mode dilithium.Mode
	dilithium.PublicKey
	dilithium.PrivateKey
}

func NewDilithiumSigner(kid string, m DilithiumMode, privKey dilithium.PrivateKey) (*DilithiumSigner, error) {
	mode := dilithium.ModeByName(m.String())
	if mode == nil {
		return nil, fmt.Errorf("unsupported dilithium mode: %s", m)
	}
	// verify the mode matches the pk, this will panic if they don't match
	publicKey := privKey.Public().(dilithium.PublicKey)
	pubKey := mode.PublicKeyFromBytes(publicKey.Bytes())
	return &DilithiumSigner{
		kid:        kid,
		mode:       mode,
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}, nil
}

func (s *DilithiumSigner) GetKeyID() string {
	return s.kid
}

func (s *DilithiumSigner) Sign(message []byte) []byte {
	return s.mode.Sign(s.PrivateKey, message)
}

type DilithiumVerifier struct {
	KID  string
	mode dilithium.Mode
	dilithium.PublicKey
}

func NewDilithiumVerifier(kid string, m DilithiumMode, pubKey dilithium.PublicKey) (*DilithiumVerifier, error) {
	mode := dilithium.ModeByName(m.String())
	if mode == nil {
		return nil, fmt.Errorf("unsupported dilithium mode: %s", m)
	}
	// verify the mode matches the pk, this will panic if they don't match
	_ = mode.PublicKeyFromBytes(pubKey.Bytes())
	return &DilithiumVerifier{
		KID:       kid,
		mode:      mode,
		PublicKey: pubKey,
	}, nil
}

func (s *DilithiumVerifier) Sign(message, signature []byte) bool {
	return s.mode.Verify(s.PublicKey, message, signature)
}
