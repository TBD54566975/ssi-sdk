package cryptosuite

import (
	"crypto"
	"encoding/json"

	"github.com/TBD54566975/did-sdk/util"
	"github.com/pkg/errors"
)

// https://w3c-ccg.github.io/ld-cryptosuite-registry/#jsonwebsignature2020

const (
	JWSSignatureSuiteID                        string = "https://w3c-ccg.github.io/security-vocab/#JsonWebSignature2020"
	JWSSignatureSuiteType                      string = "JsonWebKey2020"
	JWSSignatureSuiteCanonicalizationAlgorithm string = "https://w3id.org/security#URDNA2015"
	// JWSSignatureSuiteDigestAlgorithm uses https://www.rfc-editor.org/rfc/rfc4634
	JWSSignatureSuiteDigestAlgorithm string = "SHA-256"
	// JWSSignatureSuiteProofAlgorithm  uses https://www.rfc-editor.org/rfc/rfc7797
	JWSSignatureSuiteProofAlgorithm string = "JSON Web Signature (JWS) Unencoded Payload Option"
)

type JWSSignatureSuite struct{}

func (j JWSSignatureSuite) ID() string {
	return JWSSignatureSuiteID
}

func (j JWSSignatureSuite) Type() string {
	return JWSSignatureSuiteType
}

func (j JWSSignatureSuite) CanonicalizationAlgorithm() string {
	return JWSSignatureSuiteCanonicalizationAlgorithm
}

func (j JWSSignatureSuite) DigestAlgorithm() string {
	return JWSSignatureSuiteDigestAlgorithm
}

func (j JWSSignatureSuite) ProofAlgorithm() string {
	return JWSSignatureSuiteProofAlgorithm
}

func SignProvable(privKey crypto.PrivateKey, provable Provable) (Provable, error) {
	// JSONify the provable object
	jsonBytes, err := json.Marshal(provable)
	if err != nil {
		return nil, err
	}
	// the LD library anticipates a generic golang object to normalize
	var generic map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &generic); err != nil {
		return nil, err
	}
	normalized, err := util.LDNormalize(generic)
	if err != nil {
		return nil, errors.Wrap(err, "could not canonize provable document")
	}
	strNormalized := normalized.(string)
	return nil, nil
}

func (j JWSSignatureSuite) CreateProof(provable Provable) {
	// Create a copy of the document
	j.CanonicalizationAlgorithm()
}

func (j JWSSignatureSuite) VerifyProof() {
	//TODO implement me
	panic("implement me")
}

func (j JWSSignatureSuite) CreateVerifyHash() {
	//TODO implement me
	panic("implement me")
}
