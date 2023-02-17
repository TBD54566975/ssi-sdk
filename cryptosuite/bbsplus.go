package cryptosuite

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
	bbs "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
)

const (
	BLS12381G1Key2020 LDKeyType = "Bls12381G1Key2020"
	BLS12381G2Key2020 LDKeyType = "Bls12381G2Key2020"
)

type BBSPlusSigner struct {
	crypto.BBSPlusSigner
	purpose ProofPurpose
	format  PayloadFormat
}

func (b *BBSPlusSigner) Sign(tbs []byte) ([]byte, error) {

	return b.BBSPlusSigner.Sign(tbs)
}

func (b *BBSPlusSigner) GetKeyID() string {
	return b.BBSPlusSigner.GetKID()
}

func (*BBSPlusSigner) GetKeyType() string {
	return BLS12381G1Key2020.String()
}

func (*BBSPlusSigner) GetSignatureType() SignatureType {
	return BBSPlusSignature2020
}

func (*BBSPlusSigner) GetSigningAlgorithm() string {
	return "BBS+"
}

func (b *BBSPlusSigner) SetProofPurpose(purpose ProofPurpose) {
	b.purpose = purpose
}

func (b *BBSPlusSigner) GetProofPurpose() ProofPurpose {
	return b.purpose
}

func (b *BBSPlusSigner) SetPayloadFormat(format PayloadFormat) {
	b.format = format
}

func (b *BBSPlusSigner) GetPayloadFormat() PayloadFormat {
	return b.format
}

func NewBBSPlusSigner(kid string, privKey *bbs.PrivateKey, purpose ProofPurpose) (*BBSPlusSigner, error) {
	signer, err := crypto.NewBBSPlusSigner(kid, privKey)
	if err != nil {
		return nil, err
	}
	return &BBSPlusSigner{
		BBSPlusSigner: *signer,
		purpose:       purpose,
	}, nil
}

type BBSPlusVerifier struct {
	crypto.BBSPlusVerifier
}

func (b BBSPlusVerifier) Verify(message, signature []byte) error {
	return b.BBSPlusVerifier.Verify(signature, message)
}

func (b BBSPlusVerifier) GetKeyID() string {
	return b.BBSPlusVerifier.GetKeyID()
}

func (b BBSPlusVerifier) GetKeyType() string {
	return b.BBSPlusVerifier.GetKeyID()
}
