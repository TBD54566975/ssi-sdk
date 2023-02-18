package crypto

import (
	"crypto/rand"
	"crypto/sha256"

	bbsg2 "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
)

// GenerateBBSKeyPair https://w3c-ccg.github.io/ldp-bbs2020
func GenerateBBSKeyPair() (*bbsg2.PublicKey, *bbsg2.PrivateKey, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	return bbsg2.GenerateKeyPair(sha256.New, seed)
}

type BBSPlusSigner struct {
	kid string
	*bbsg2.PrivateKey
	*bbsg2.PublicKey
}

func NewBBSPlusSigner(kid string, privKey *bbsg2.PrivateKey) (*BBSPlusSigner, error) {
	return &BBSPlusSigner{
		kid:        kid,
		PrivateKey: privKey,
		PublicKey:  privKey.PublicKey(),
	}, nil
}

func (s *BBSPlusSigner) GetKeyID() string {
	return s.kid
}

func (s *BBSPlusSigner) Sign(messages ...[]byte) ([]byte, error) {
	bls := bbsg2.New()
	return bls.SignWithKey(messages, s.PrivateKey)
}

func (s *BBSPlusSigner) Verify(message []byte, signature []byte) error {
	bls := bbsg2.New()
	pubKeyBytes, err := s.PublicKey.Marshal()
	if err != nil {
		return err
	}
	return bls.Verify([][]byte{message}, signature, pubKeyBytes)
}

func (s *BBSPlusSigner) VerifyMultiple(signature []byte, messages ...[]byte) error {
	bls := bbsg2.New()
	pubKeyBytes, err := s.PublicKey.Marshal()
	if err != nil {
		return err
	}
	return bls.Verify(messages, signature, pubKeyBytes)
}

func (s *BBSPlusSigner) ToVerifier() (*BBSPlusVerifier, error) {
	return NewBBSPlusVerifier(s.kid, s.PublicKey)
}

type BBSPlusVerifier struct {
	kid string
	*bbsg2.PublicKey
}

func NewBBSPlusVerifier(kid string, pubKey *bbsg2.PublicKey) (*BBSPlusVerifier, error) {
	return &BBSPlusVerifier{
		kid:       kid,
		PublicKey: pubKey,
	}, nil
}

func (s *BBSPlusVerifier) GetKeyID() string {
	return s.kid
}

func (s *BBSPlusVerifier) Verify(message []byte, signature []byte) error {
	bls := bbsg2.New()
	pubKeyBytes, err := s.PublicKey.Marshal()
	if err != nil {
		return err
	}
	return bls.Verify([][]byte{message}, signature, pubKeyBytes)
}

func (s *BBSPlusVerifier) VerifyMultiple(signature []byte, messages ...[]byte) error {
	bls := bbsg2.New()
	pubKeyBytes, err := s.PublicKey.Marshal()
	if err != nil {
		return err
	}
	return bls.Verify(messages, signature, pubKeyBytes)
}

// Utility methods to be used without a signer

func SignBBSMessage(privKey *bbsg2.PrivateKey, messages ...[]byte) ([]byte, error) {
	bls := bbsg2.New()
	return bls.SignWithKey(messages, privKey)
}

func VerifyBBSMessage(pubKey *bbsg2.PublicKey, signature []byte, messages ...[]byte) error {
	bls := bbsg2.New()
	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		return err
	}
	return bls.Verify(messages, signature, pubKeyBytes)
}
