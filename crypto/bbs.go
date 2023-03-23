package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"

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
	*BBSPlusVerifier
}

func NewBBSPlusSigner(kid string, privKey *bbsg2.PrivateKey) *BBSPlusSigner {
	pubKey := privKey.PublicKey()
	return &BBSPlusSigner{
		kid:        kid,
		PrivateKey: privKey,
		PublicKey:  pubKey,
		BBSPlusVerifier: &BBSPlusVerifier{
			KID:       kid,
			PublicKey: pubKey,
		},
	}
}

func (s *BBSPlusSigner) GetKeyID() string {
	return s.kid
}

func (s *BBSPlusSigner) Sign(message []byte) ([]byte, error) {
	bls := bbsg2.New()
	return bls.SignWithKey(prepareBBSMessage(message), s.PrivateKey)
}

func (s *BBSPlusSigner) SignMultiple(messages ...[]byte) ([]byte, error) {
	bls := bbsg2.New()
	return bls.SignWithKey(messages, s.PrivateKey)
}

func (s *BBSPlusSigner) GetVerifier() *BBSPlusVerifier {
	return s.BBSPlusVerifier
}

type BBSPlusVerifier struct {
	KID string
	*bbsg2.PublicKey
}

func NewBBSPlusVerifier(kid string, pubKey *bbsg2.PublicKey) *BBSPlusVerifier {
	return &BBSPlusVerifier{
		KID:       kid,
		PublicKey: pubKey,
	}
}

func (v *BBSPlusVerifier) GetKeyID() string {
	return v.KID
}

func (v *BBSPlusVerifier) Verify(message, signature []byte) error {
	bls := bbsg2.New()
	pubKeyBytes, err := v.PublicKey.Marshal()
	if err != nil {
		return err
	}
	return bls.Verify(prepareBBSMessage(message), signature, pubKeyBytes)
}

// VerifyDerived verifies a derived proof, or a selective disclosure proof that has been derived from a
// BBSPlusSignature signed object.
func (v *BBSPlusVerifier) VerifyDerived(message, signature, nonce []byte) error {
	bls := bbsg2.New()
	pubKeyBytes, err := v.PublicKey.Marshal()
	if err != nil {
		return err
	}
	return bls.VerifyProof(prepareBBSDerivedMessage(message), signature, nonce, pubKeyBytes)
}

func (v *BBSPlusVerifier) VerifyMultiple(signature []byte, messages ...[]byte) error {
	bls := bbsg2.New()
	pubKeyBytes, err := v.PublicKey.Marshal()
	if err != nil {
		return err
	}
	return bls.Verify(messages, signature, pubKeyBytes)
}

func (v *BBSPlusVerifier) DeriveProof(messages [][]byte, sigBytes, nonce []byte, revealedIndexes []int) ([]byte, error) {
	bls := bbsg2.New()
	pubKeyBytes, err := v.PublicKey.Marshal()
	if err != nil {
		return nil, err
	}
	return bls.DeriveProof(messages, sigBytes, nonce, pubKeyBytes, revealedIndexes)
}

// Utility methods to be used without a signer

func SignBBSMessage(privKey *bbsg2.PrivateKey, messages ...[]byte) ([]byte, error) {
	signer := BBSPlusSigner{
		PrivateKey: privKey,
	}
	return signer.SignMultiple(messages...)
}

func VerifyBBSMessage(pubKey *bbsg2.PublicKey, signature, message []byte) error {
	verifier := BBSPlusVerifier{
		PublicKey: pubKey,
	}
	return verifier.Verify(message, signature)
}

func VerifyDerivedBBSMessage(pubKey *bbsg2.PublicKey, signature, message, nonce []byte) error {
	verifier := BBSPlusVerifier{
		PublicKey: pubKey,
	}
	return verifier.VerifyDerived(message, signature, nonce)
}

// helpers

// prepareBBSMessage transforms a message into a message that can be used to verify a BBS+ signature
// as per https://w3c-ccg.github.io/ldp-bbs2020/#create-verify-data-algorithm
func prepareBBSMessage(msg []byte) [][]byte {
	rows := strings.Split(string(msg), "\n")
	msgs := make([][]byte, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row) == "" {
			continue
		}
		msgs = append(msgs, []byte(row))
	}
	return msgs
}

// prepareBBSDerivedMessage transforms a message from a derived proof into a message that can be used
// to verify the derived proof as per https://w3c-ccg.github.io/ldp-bbs2020/#create-verify-data-algorithm
func prepareBBSDerivedMessage(msg []byte) [][]byte {
	rows := strings.Split(string(msg), "\n")
	msgs := make([][]byte, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row) == "" {
			continue
		}
		transformedRow := transformFromBlankNode(row)
		msgs = append(msgs, []byte(transformedRow))
	}
	return msgs
}

// necessary to patch this version of the go JSON-LD library; taken from:
// https://github.com/hyperledger/aries-framework-go/blob/02f80847168a99c8eb3baeaafcba8d0367bd9551/pkg/doc/signature/jsonld/processor.go#L453
func transformFromBlankNode(row string) string {
	// transform from "urn:bnid:_:c14n0" to "_:c14n0"
	const (
		emptyNodePlaceholder = "<urn:bnid:_:c14n"
		emptyNodePrefixLen   = 10
	)

	prefixIndex := strings.Index(row, emptyNodePlaceholder)
	if prefixIndex < 0 {
		return row
	}

	sepIndex := strings.Index(row[prefixIndex:], ">")
	if sepIndex < 0 {
		return row
	}

	sepIndex += prefixIndex

	prefix := row[:prefixIndex]
	blankNode := row[prefixIndex+emptyNodePrefixLen : sepIndex]
	suffix := row[sepIndex+1:]

	return fmt.Sprintf("%s%s%s", prefix, blankNode, suffix)
}
