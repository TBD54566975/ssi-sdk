package cryptosuite

import (
	gocrypto "crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
	. "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// https://w3c-ccg.github.io/ld-cryptosuite-registry/#jsonwebsignature2020

const (
	JSONWebSignature2020Context                string        = "https://w3id.org/security/suites/jws-2020/v1"
	JSONWebSignature2020                       SignatureType = "JsonWebSignature2020"
	JWSSignatureSuiteID                        string        = "https://w3c-ccg.github.io/security-vocab/#JsonWebSignature2020"
	JWSSignatureSuiteType                      LDKeyType     = JSONWebKey2020Type
	JWSSignatureSuiteCanonicalizationAlgorithm string        = "https://w3id.org/security#URDNA2015"
	// JWSSignatureSuiteDigestAlgorithm uses https://www.rfc-editor.org/rfc/rfc4634
	JWSSignatureSuiteDigestAlgorithm gocrypto.Hash = gocrypto.SHA256
	// JWSSignatureSuiteProofAlgorithm  uses https://www.rfc-editor.org/rfc/rfc7797
	JWSSignatureSuiteProofAlgorithm = JSONWebSignature2020
)

type JWSSignatureSuite struct {
	CryptoSuiteProofType
}

func GetJSONWebSignature2020Suite() CryptoSuite {
	return new(JWSSignatureSuite)
}

// CryptoSuiteInfo interface

func (JWSSignatureSuite) ID() string {
	return JWSSignatureSuiteID
}

func (JWSSignatureSuite) Type() LDKeyType {
	return JWSSignatureSuiteType
}

func (JWSSignatureSuite) CanonicalizationAlgorithm() string {
	return JWSSignatureSuiteCanonicalizationAlgorithm
}

func (JWSSignatureSuite) MessageDigestAlgorithm() gocrypto.Hash {
	return JWSSignatureSuiteDigestAlgorithm
}

func (JWSSignatureSuite) SignatureAlgorithm() SignatureType {
	return JWSSignatureSuiteProofAlgorithm
}

func (JWSSignatureSuite) RequiredContexts() []string {
	return []string{JSONWebSignature2020Context}
}

func (j JWSSignatureSuite) Sign(s Signer, p Provable) error {
	// create proof before CVH
	proof := j.createProof(s.GetKeyID(), s.GetProofPurpose())

	// prepare proof options
	contexts, err := GetContextsFromProvable(p)
	if err != nil {
		return errors.Wrap(err, "could not get contexts from provable")
	}

	// make sure the suite's context(s) are included
	contexts = ensureRequiredContexts(contexts, j.RequiredContexts())
	opts := &ProofOptions{Contexts: contexts}

	// 3. tbs value as a result of cvh
	tbs, err := j.CreateVerifyHash(p, proof, opts)
	if err != nil {
		return errors.Wrap(err, "create verify hash algorithm failed")
	}

	// 4 & 5. create the signature over the provable data as a JWS
	signature, err := s.Sign(tbs)
	if err != nil {
		return errors.Wrap(err, "could not sign provable value")
	}

	// set the signature on the proof object and return
	proof.SetDetachedJWS(string(signature))
	genericProof := crypto.Proof(proof)
	p.SetProof(&genericProof)
	return nil
}

func (j JWSSignatureSuite) Verify(v Verifier, p Provable) error {
	proof := p.GetProof()
	gotProof, err := JSONWebSignatureProofFromGenericProof(*proof)
	if err != nil {
		return errors.Wrap(err, "could not prepare proof for verification; error coercing proof into JsonWebSignature2020 proof")
	}

	// remove proof before verifying
	p.SetProof(nil)

	// make sure we set it back after we're done verifying
	defer p.SetProof(proof)

	// remove the JWS value in the proof before verification
	jwsCopy := []byte(gotProof.JWS)
	gotProof.SetDetachedJWS("")

	// prepare proof options
	contexts, err := GetContextsFromProvable(p)
	if err != nil {
		return errors.Wrap(err, "could not get contexts from provable")
	}

	// make sure the suite's context(s) are included
	contexts = ensureRequiredContexts(contexts, j.RequiredContexts())
	opts := &ProofOptions{Contexts: contexts}

	// run CVH on both provable and the proof
	tbv, err := j.CreateVerifyHash(p, gotProof, opts)
	if err != nil {
		return errors.Wrap(err, "create verify hash algorithm failed")
	}

	if err = v.Verify(tbv, jwsCopy); err != nil {
		return errors.Wrap(err, "could not verify JWS")
	}
	return nil
}

// CryptoSuiteProofType interface

func (JWSSignatureSuite) Marshal(data interface{}) ([]byte, error) {
	// JSONify the provable object
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

func (JWSSignatureSuite) Canonicalize(marshaled []byte) (*string, error) {
	// the LD library anticipates a generic golang json object to normalize
	var generic map[string]interface{}
	if err := json.Unmarshal(marshaled, &generic); err != nil {
		return nil, err
	}
	normalized, err := LDNormalize(generic)
	if err != nil {
		return nil, errors.Wrap(err, "could not canonicalize provable document")
	}
	canonicalString := normalized.(string)
	return &canonicalString, nil
}

func (j JWSSignatureSuite) CreateVerifyHash(provable Provable, proof crypto.Proof, opts *ProofOptions) ([]byte, error) {
	// first, make sure "created" exists in the proof and insert an LD context property for the proof vocabulary
	preparedProof, err := j.prepareProof(proof, opts)
	if err != nil {
		return nil, errors.Wrap(err, "could not prepare proof for the create verify hash algorithm")
	}

	// marshal provable to prepare for canonicalizaiton
	marshaledProvable, err := j.Marshal(provable)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal provable")
	}

	// canonicalize provable using the suite's method
	canonicalProvable, err := j.Canonicalize(marshaledProvable)
	if err != nil {
		return nil, errors.Wrap(err, "could not canonicalize provable")
	}

	// marshal proof to prepare for canonicalizaiton
	marshaledOptions, err := j.Marshal(preparedProof)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal proof")
	}

	// 4.1 canonicalize  proof using the suite's method
	canonicalizedOptions, err := j.Canonicalize(marshaledOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not canonicalize proof")
	}

	// 4.2 set output to the result of the hash of the canonicalized options document
	canonicalizedOptionsBytes := []byte(*canonicalizedOptions)
	optionsDigest, err := j.Digest(canonicalizedOptionsBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not take digest of proof")
	}

	// 4.3 hash the canonicalized doc and append it to the output
	canonicalDoc := []byte(*canonicalProvable)
	documentDigest, err := j.Digest(canonicalDoc)
	if err != nil {
		return nil, errors.Wrap(err, "could not take digest of provable")
	}

	// 5. return the output
	output := append(optionsDigest, documentDigest...)
	return output, nil
}

func (j JWSSignatureSuite) Digest(tbd []byte) ([]byte, error) {
	if j.MessageDigestAlgorithm() != gocrypto.SHA256 {
		return nil, fmt.Errorf("unexpected digest algorithm: %s", j.MessageDigestAlgorithm().String())
	}
	hash := sha256.Sum256(tbd)
	return hash[:], nil
}

func (j JWSSignatureSuite) prepareProof(proof crypto.Proof, opts *ProofOptions) (*crypto.Proof, error) {
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}

	var genericProof map[string]interface{}
	if err = json.Unmarshal(proofBytes, &genericProof); err != nil {
		return nil, err
	}

	// proof cannot have a jws value
	delete(genericProof, "jws")

	// make sure the proof has a timestamp
	created, ok := genericProof["created"]
	if !ok || created == "" {
		genericProof["created"] = GetRFC3339Timestamp()
	}

	var contexts []interface{}
	if opts != nil && len(opts.Contexts) > 0 {
		contexts = opts.Contexts
	} else {
		// if none provided, make sure the proof has a context value for this suite
		contexts = ArrayStrToInterface(j.RequiredContexts())
	}
	genericProof["@context"] = contexts
	p := crypto.Proof(genericProof)
	return &p, nil
}

type JSONWebSignature2020Proof struct {
	Type               SignatureType `json:"type,omitempty"`
	Created            string        `json:"created,omitempty"`
	JWS                string        `json:"jws,omitempty"`
	ProofPurpose       ProofPurpose  `json:"proofPurpose,omitempty"`
	Challenge          string        `json:"challenge,omitempty"`
	VerificationMethod string        `json:"verificationMethod,omitempty"`
}

func JSONWebSignatureProofFromGenericProof(p crypto.Proof) (*JSONWebSignature2020Proof, error) {
	proofBytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var generic map[string]interface{}
	if err = json.Unmarshal(proofBytes, &generic); err != nil {
		return nil, err
	}
	typeValue, ok := generic["type"].(string)
	if !ok {
		typeValue = ""
	}
	createdValue, ok := generic["created"].(string)
	if !ok {
		createdValue = ""
	}
	jwsValue, ok := generic["jws"].(string)
	if !ok {
		jwsValue = ""
	}
	purposeValue, ok := generic["proofPurpose"].(string)
	if !ok {
		purposeValue = ""
	}
	challengeValue, ok := generic["challenge"].(string)
	if !ok {
		challengeValue = ""
	}
	methodValue, ok := generic["verificationMethod"].(string)
	if !ok {
		methodValue = ""
	}
	return &JSONWebSignature2020Proof{
		Type:               SignatureType(typeValue),
		Created:            createdValue,
		JWS:                jwsValue,
		ProofPurpose:       ProofPurpose(purposeValue),
		Challenge:          challengeValue,
		VerificationMethod: methodValue,
	}, nil
}

func (j *JSONWebSignature2020Proof) ToGenericProof() crypto.Proof {
	return j
}

func (j *JSONWebSignature2020Proof) SetDetachedJWS(jws string) {
	if j != nil {
		j.JWS = jws
	}
}

func (j *JSONWebSignature2020Proof) GetDetachedJWS() string {
	if j != nil {
		return ""
	}
	return j.JWS
}

func (j *JSONWebSignature2020Proof) DecodeJWS() ([]byte, error) {
	if j == nil {
		return nil, errors.New("cannot decode jws on empty proof")
	}
	jwsParts := strings.Split(j.JWS, ".")
	if len(jwsParts) != 3 {
		return nil, errors.New("malformed jws")
	}
	return base64.RawURLEncoding.DecodeString(jwsParts[2])
}

func (j JWSSignatureSuite) createProof(verificationMethod string, purpose ProofPurpose) JSONWebSignature2020Proof {
	var challenge string
	if purpose == Authentication {
		challenge = uuid.NewString()
	}
	return JSONWebSignature2020Proof{
		Type:               j.SignatureAlgorithm(),
		Created:            GetRFC3339Timestamp(),
		ProofPurpose:       purpose,
		Challenge:          challenge,
		VerificationMethod: verificationMethod,
	}
}
