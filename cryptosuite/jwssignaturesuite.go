package cryptosuite

import (
	gocrypto "crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/crypto"
	. "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"strings"
)

// https://w3c-ccg.github.io/ld-cryptosuite-registry/#jsonwebsignature2020

const (
	JSONWebSignature2020Context                string        = "https://w3id.org/security/suites/jws-2020/v1"
	JSONWebSignature2020                       SignatureType = "JsonWebSignature2020"
	JWSSignatureSuiteID                        string        = "https://w3c-ccg.github.io/security-vocab/#JsonWebSignature2020"
	JWSSignatureSuiteType                      LDKeyType     = JsonWebKey2020
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
	return &JWSSignatureSuite{}
}

// CryptoSuiteInfo interface

func (j JWSSignatureSuite) ID() string {
	return JWSSignatureSuiteID
}

func (j JWSSignatureSuite) Type() LDKeyType {
	return JWSSignatureSuiteType
}

func (j JWSSignatureSuite) CanonicalizationAlgorithm() string {
	return JWSSignatureSuiteCanonicalizationAlgorithm
}

func (j JWSSignatureSuite) MessageDigestAlgorithm() gocrypto.Hash {
	return JWSSignatureSuiteDigestAlgorithm
}

func (j JWSSignatureSuite) SignatureAlgorithm() SignatureType {
	return JWSSignatureSuiteProofAlgorithm
}

func (j JWSSignatureSuite) RequiredContexts() []string {
	return []string{JSONWebSignature2020Context}
}

func (j JWSSignatureSuite) Sign(s Signer, p Provable) error {
	// create proof before CVH
	proof := j.createProof(s.GetKeyID(), s.GetProofPurpose())

	// prepare proof options
	contexts, err := GetContextsFromProvable(p)
	if err != nil {
		err := errors.Wrap(err, "could not get contexts from provable")
		logrus.WithError(err).Error()
		return err
	}

	// make sure the suite's context(s) are included
	contexts = ensureRequiredContexts(contexts, j.RequiredContexts())
	opts := &ProofOptions{Contexts: contexts}

	// 3. tbs value as a result of cvh
	tbs, err := j.CreateVerifyHash(p, proof, opts)
	if err != nil {
		logrus.WithError(err).Error("create verify hash algorithm failed")
		return err
	}

	// 4 & 5. create the signature over the provable data as a JWS
	signature, err := s.Sign(tbs)
	if err != nil {
		logrus.WithError(err).Error("could not sign provable value")
		return err
	}

	// set the signature on the proof object and return
	proof.SetDetachedJWS(string(signature))
	genericProof := crypto.Proof(proof)
	p.SetProof(&genericProof)
	return nil
}

func (j JWSSignatureSuite) Verify(v Verifier, p Provable) error {
	proof := p.GetProof()
	gotProof, err := FromGenericProof(*proof)
	if err != nil {
		err := errors.Wrap(err, "could not coerce proof into JsonWebSignature2020 proof")
		logrus.WithError(err).Error("could not prepare proof for verification")
		return err
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
		err := errors.Wrap(err, "could not get contexts from provable")
		logrus.WithError(err).Error()
		return err
	}

	// make sure the suite's context(s) are included
	contexts = ensureRequiredContexts(contexts, j.RequiredContexts())
	opts := &ProofOptions{Contexts: contexts}

	// run CVH on both provable and the proof
	tbv, err := j.CreateVerifyHash(p, gotProof, opts)
	if err != nil {
		logrus.WithError(err).Error("create verify hash algorithm failed")
		return err
	}

	if err = v.Verify(tbv, jwsCopy); err != nil {
		logrus.WithError(err).Error("could not verify JWS")
		return err
	}
	return nil
}

// CryptoSuiteProofType interface

func (j JWSSignatureSuite) Marshal(data interface{}) ([]byte, error) {
	// JSONify the provable object
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

func (j JWSSignatureSuite) Canonicalize(marshaled []byte) (*string, error) {
	// the LD library anticipates a generic golang json object to normalize
	var generic map[string]interface{}
	if err := json.Unmarshal(marshaled, &generic); err != nil {
		return nil, err
	}
	normalized, err := LDNormalize(generic)
	if err != nil {
		err := errors.Wrap(err, "could not canonicalize provable document")
		logrus.WithError(err).Error()
		return nil, err
	}
	canonicalString := normalized.(string)
	return &canonicalString, nil
}

func (j JWSSignatureSuite) CreateVerifyHash(provable Provable, proof crypto.Proof, opts *ProofOptions) ([]byte, error) {
	// first, make sure "created" exists in the proof and insert an LD context property for the proof vocabulary
	preparedProof, err := j.prepareProof(proof, opts)
	if err != nil {
		errMsg := "could not prepare proof for the create verify hash algorithm"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// marshal provable to prepare for canonicalizaiton
	marshaledProvable, err := j.Marshal(provable)
	if err != nil {
		errMsg := "could not marshal provable"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// canonicalize provable using the suite's method
	canonicalProvable, err := j.Canonicalize(marshaledProvable)
	if err != nil {
		errMsg := "could not canonicalize provable"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// marshal proof to prepare for canonicalizaiton
	marshaledOptions, err := j.Marshal(preparedProof)
	if err != nil {
		errMsg := "could not marshal proof"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// 4.1 canonicalize  proof using the suite's method
	canonicalizedOptions, err := j.Canonicalize(marshaledOptions)
	if err != nil {
		errMsg := "could not canonicalize proof"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// 4.2 set output to the result of the hash of the canonicalized options document
	canonicalizedOptionsBytes := []byte(*canonicalizedOptions)
	optionsDigest, err := j.Digest(canonicalizedOptionsBytes)
	if err != nil {
		errMsg := "could not take digest of proof"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// 4.3 hash the canonicalized doc and append it to the output
	canonicalDoc := []byte(*canonicalProvable)
	documentDigest, err := j.Digest(canonicalDoc)
	if err != nil {
		errMsg := "could not take digest of provable"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// 5. return the output
	output := append(optionsDigest, documentDigest...)
	return output, nil
}

func (j JWSSignatureSuite) Digest(tbd []byte) ([]byte, error) {
	if j.MessageDigestAlgorithm() != gocrypto.SHA256 {
		err := fmt.Errorf("unexpected digest algorithm: %s", j.MessageDigestAlgorithm().String())
		logrus.WithError(err).Error("could not get digest")
		return nil, err
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
	if err := json.Unmarshal(proofBytes, &genericProof); err != nil {
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
	if opts != nil {
		contexts = opts.Contexts
	} else {
		// if none provided, make sure the proof has a context value for this suite
		contexts = ArrayStrToInterface(j.RequiredContexts())
	}
	genericProof["@context"] = contexts
	p := crypto.Proof(genericProof)
	return &p, nil
}

type JsonWebSignature2020Proof struct {
	Type               SignatureType `json:"type,omitempty"`
	Created            string        `json:"created,omitempty"`
	JWS                string        `json:"jws,omitempty"`
	ProofPurpose       ProofPurpose  `json:"proofPurpose,omitempty"`
	Challenge          string        `json:"challenge,omitempty"`
	VerificationMethod string        `json:"verificationMethod,omitempty"`
}

func FromGenericProof(p crypto.Proof) (*JsonWebSignature2020Proof, error) {
	proofBytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(proofBytes, &generic); err != nil {
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
	return &JsonWebSignature2020Proof{
		Type:               SignatureType(typeValue),
		Created:            createdValue,
		JWS:                jwsValue,
		ProofPurpose:       ProofPurpose(purposeValue),
		Challenge:          challengeValue,
		VerificationMethod: methodValue,
	}, nil
}

func (j *JsonWebSignature2020Proof) ToGenericProof() crypto.Proof {
	return j
}

func (j *JsonWebSignature2020Proof) SetDetachedJWS(jws string) {
	if j != nil {
		j.JWS = jws
	}
}

func (j *JsonWebSignature2020Proof) GetDetachedJWS() string {
	if j != nil {
		return ""
	}
	return j.JWS
}

func (j *JsonWebSignature2020Proof) DecodeJWS() ([]byte, error) {
	if j == nil {
		return nil, errors.New("cannot decode jws on empty proof")
	}
	jwsParts := strings.Split(j.JWS, ".")
	if len(jwsParts) != 3 {
		return nil, errors.New("malformed jws")
	}
	return base64.RawURLEncoding.DecodeString(jwsParts[2])
}

func (j JWSSignatureSuite) createProof(verificationMethod string, purpose ProofPurpose) JsonWebSignature2020Proof {
	var challenge string
	if purpose == Authentication {
		challenge = uuid.NewString()
	}
	return JsonWebSignature2020Proof{
		Type:               j.SignatureAlgorithm(),
		Created:            GetRFC3339Timestamp(),
		ProofPurpose:       purpose,
		Challenge:          challenge,
		VerificationMethod: verificationMethod,
	}
}
