package crypto

import (
	"crypto/rand"
	"crypto/sha256"

	bbs "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
)

// GenerateBBSKeyPair https://w3c-ccg.github.io/ldp-bbs2020
func GenerateBBSKeyPair() (*bbs.PublicKey, *bbs.PrivateKey, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	return bbs.GenerateKeyPair(sha256.New, seed)
}

type BBSPlusSigner struct {
	kid string
	*bbs.PrivateKey
	*bbs.PublicKey
}

func NewBBSPlusSigner(kid string, privKey *bbs.PrivateKey) (*BBSPlusSigner, error) {
	return &BBSPlusSigner{
		kid:        kid,
		PrivateKey: privKey,
		PublicKey:  privKey.PublicKey(),
	}, nil
}

func (s *BBSPlusSigner) GetKID() string {
	return s.kid
}

func (s *BBSPlusSigner) Sign(messages ...[]byte) ([]byte, error) {
	bls := bbs.New()
	return bls.SignWithKey(messages, s.PrivateKey)
}

func (s *BBSPlusSigner) Verify(signature []byte, messages ...[]byte) error {
	bls := bbs.New()
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
	*bbs.PublicKey
}

func NewBBSPlusVerifier(kid string, pubKey *bbs.PublicKey) (*BBSPlusVerifier, error) {
	return &BBSPlusVerifier{
		kid:       kid,
		PublicKey: pubKey,
	}, nil
}

func (s *BBSPlusVerifier) GetKeyID() string {
	return s.kid
}

func (s *BBSPlusVerifier) Verify(signature []byte, messages ...[]byte) error {
	bls := bbs.New()
	pubKeyBytes, err := s.PublicKey.Marshal()
	if err != nil {
		return err
	}
	return bls.Verify(messages, signature, pubKeyBytes)
}

// Utility methods to be used without a signer

func SignBBSMessage(privKey *bbs.PrivateKey, messages ...[]byte) ([]byte, error) {
	bls := bbs.New()
	return bls.SignWithKey(messages, privKey)
}

func VerifyBBSMessage(pubKey *bbs.PublicKey, signature []byte, messages ...[]byte) error {
	bls := bbs.New()
	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		return err
	}
	return bls.Verify(messages, signature, pubKeyBytes)
}
