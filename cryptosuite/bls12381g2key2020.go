package cryptosuite

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
	bbs "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/mr-tron/base58"
)

const (
	BLS12381G2Key2020 LDKeyType = "Bls12381G2Key2020"

	G1 CRV = "BLS12381_G1"
	G2 CRV = "BLS12381_G2"
)

type BLSKey2020 struct {
	ID         string    `json:"id,omitempty"`
	Type       LDKeyType `json:"type,omitempty"`
	Controller string    `json:"controller,omitempty"`

	// One of public key base 58 or public key JWK is required
	PublicKeyBase58  string `json:"publicKeyBase58,omitempty"`
	PrivateKeyBase58 string `json:"privateKeyBase58,omitempty"`
}

func (b BLSKey2020) GetPublicKey() (*bbs.PublicKey, error) {
	pubKeyBytes, err := base58.Decode(b.PublicKeyBase58)
	if err != nil {
		return nil, err
	}
	publicKey, err := bbs.UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func (b BLSKey2020) GetPrivateKey() (*bbs.PrivateKey, error) {
	privKeyBytes, err := base58.Decode(b.PrivateKeyBase58)
	if err != nil {
		return nil, err
	}
	privateKey, err := bbs.UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// GenerateBLSKey2020 https://w3c-ccg.github.io/ldp-bbs2020/#bls-12-381-g2-public-key
func GenerateBLSKey2020() (*BLSKey2020, error) {
	pubKey, privKey, err := crypto.GenerateBBSKeyPair()
	if err != nil {
		return nil, err
	}
	pubKeyBytes, err := pubKey.Marshal()
	if err != nil {
		return nil, err
	}
	privKeyBytes, err := privKey.Marshal()
	if err != nil {
		return nil, err
	}
	return &BLSKey2020{
		Type:             BLS12381G2Key2020,
		PublicKeyBase58:  base58.Encode(pubKeyBytes),
		PrivateKeyBase58: base58.Encode(privKeyBytes),
	}, nil
}

type BBSPlusSigner struct {
	*crypto.BBSPlusSigner
	*crypto.BBSPlusVerifier
	purpose ProofPurpose
	format  PayloadFormat
}

func NewBBSPlusSigner(kid string, privKey *bbs.PrivateKey, purpose ProofPurpose) *BBSPlusSigner {
	signer := crypto.NewBBSPlusSigner(kid, privKey)
	return &BBSPlusSigner{
		BBSPlusSigner:   signer,
		BBSPlusVerifier: signer.BBSPlusVerifier,
		purpose:         purpose,
	}
}

func (s *BBSPlusSigner) Sign(tbs []byte) ([]byte, error) {
	return s.BBSPlusSigner.Sign(tbs)
}

func (s *BBSPlusSigner) GetKeyID() string {
	return s.BBSPlusSigner.GetKeyID()
}

func (*BBSPlusSigner) GetSignatureType() SignatureType {
	return BBSPlusSignature2020
}

func (*BBSPlusSigner) GetSigningAlgorithm() string {
	return string(BBSPlusSignature2020)
}

func (s *BBSPlusSigner) SetProofPurpose(purpose ProofPurpose) {
	s.purpose = purpose
}

func (s *BBSPlusSigner) GetProofPurpose() ProofPurpose {
	return s.purpose
}

func (s *BBSPlusSigner) SetPayloadFormat(format PayloadFormat) {
	s.format = format
}

func (s *BBSPlusSigner) GetPayloadFormat() PayloadFormat {
	return s.format
}

type BBSPlusVerifier struct {
	*crypto.BBSPlusVerifier
}

func NewBBSPlusVerifier(kid string, pubKey *bbs.PublicKey) *BBSPlusVerifier {
	return &BBSPlusVerifier{
		BBSPlusVerifier: crypto.NewBBSPlusVerifier(kid, pubKey),
	}
}

func (v BBSPlusVerifier) DeriveProof(messages [][]byte, sigBytes, nonce []byte, revealedIndexes []int) ([]byte, error) {
	return v.BBSPlusVerifier.DeriveProof(messages, sigBytes, nonce, revealedIndexes)
}

func (v BBSPlusVerifier) Verify(message, signature []byte) error {
	return v.BBSPlusVerifier.Verify(message, signature)
}

func (v BBSPlusVerifier) VerifyDerived(message, signature []byte) error {
	return v.BBSPlusVerifier.VerifyDerived(message, signature)
}

func (v BBSPlusVerifier) GetKeyID() string {
	return v.BBSPlusVerifier.GetKeyID()
}
