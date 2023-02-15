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
