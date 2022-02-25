package cryptosuite

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TBD54566975/did-sdk/util"
	"github.com/pkg/errors"
)

// https://w3c-ccg.github.io/ld-cryptosuite-registry/#jsonwebsignature2020

const (
	JSONWebSignature2020Context                string        = "https://w3id.org/security/suites/jws-2020/v1"
	JSONWebSignature2020                       SignatureType = "JsonWebSignature2020"
	JWSSignatureSuiteID                        string        = "https://w3c-ccg.github.io/security-vocab/#JsonWebSignature2020"
	JWSSignatureSuiteType                                    = JsonWebKey2020
	JWSSignatureSuiteCanonicalizationAlgorithm string        = "https://w3id.org/security#URDNA2015"
	// JWSSignatureSuiteDigestAlgorithm uses https://www.rfc-editor.org/rfc/rfc4634
	JWSSignatureSuiteDigestAlgorithm crypto.Hash = crypto.SHA256
	// JWSSignatureSuiteProofAlgorithm  uses https://www.rfc-editor.org/rfc/rfc7797
	JWSSignatureSuiteProofAlgorithm = JSONWebSignature2020
)

type JWSSignatureSuite struct {
	CryptoSuiteProofType
}

func (j JWSSignatureSuite) ID() string {
	return JWSSignatureSuiteID
}

func (j JWSSignatureSuite) Type() KeyType {
	return JWSSignatureSuiteType
}

func (j JWSSignatureSuite) CanonicalizationAlgorithm() string {
	return JWSSignatureSuiteCanonicalizationAlgorithm
}

func (j JWSSignatureSuite) MessageDigestAlgorithm() crypto.Hash {
	return JWSSignatureSuiteDigestAlgorithm
}

func (j JWSSignatureSuite) SignatureAlgorithm() SignatureType {
	return JWSSignatureSuiteProofAlgorithm
}

func (j JWSSignatureSuite) RequiredContexts() []string {
	return []string{JSONWebSignature2020Context}
}

func (j JWSSignatureSuite) Sign(s Signer, p Provable) (*Provable, error) {
	// before we can create a proof we need to make sure the document contains the requisite
	// JSON-LD context for this signature suite
	if err := j.verifySuiteContext(p); err != nil {
		return nil, err
	}

	// marshal provable to prepare for canonicalizaiton
	marshaledDocument, err := j.Marshal(p)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal provable")
	}

	// 2. canonicalize provable using the suite's method
	canonicalizedDocument, err := j.Canonicalize(marshaledDocument)
	if err != nil {
		return nil, errors.Wrap(err, "could not canonicalize provable")
	}

	// create proof before CVH
	proof := j.createProof(s.KeyID())

	// 3. tbs value as a result of cvh
	tbs, err := j.CreateVerifyHash([]byte(*canonicalizedDocument), proof)
	if err != nil {
		return nil, err
	}

	// 4. create the signature over the provable data
	signature, err := s.Sign(tbs)
	if err != nil {
		return nil, err
	}

	// 5. prepare the JWS value to be set as the `signature` in the proof block
	detachedJWS, err := j.createDetachedJWS(s.SigningAlgorithm(), signature)
	if err != nil {
		return nil, err
	}

	proof.SetDetachedJWS(*detachedJWS)
	genericProof := Proof(proof)
	p.SetProof(&genericProof)
	return &p, nil
}

func (j JWSSignatureSuite) Verify(v Verifier, p Provable) error {
	proof := p.GetProof()
	gotProof, err := FromGenericProof(*proof)
	if err != nil {
		return errors.Wrap(err, "could not coerce proof into JsonWebSignature2020 proof")
	}

	// remove proof before verifying
	p.SetProof(nil)

	// pull off JWS to get signature
	decodedJWS, err := gotProof.DecodeJWS()
	if err != nil {
		return errors.Wrap(err, "could not decode jws")
	}

	// remove the JWS value in the proof before verification
	gotProof.SetDetachedJWS("")

	// marshal provable to prepare for canonicalizaiton
	marshaledProvable, err := j.Marshal(p)
	if err != nil {
		return errors.Wrap(err, "could not marshal provable")
	}

	// canonicalize provable using the suite's method
	canonicalProvable, err := j.Canonicalize(marshaledProvable)
	if err != nil {
		return errors.Wrap(err, "could not canonicalize provable")
	}

	// run CVH on both provable and the proof
	tbv, err := j.CreateVerifyHash([]byte(*canonicalProvable), proof)
	if err != nil {
		return err
	}

	return v.Verify(tbv, decodedJWS)
}

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
	normalized, err := util.LDNormalize(generic)
	if err != nil {
		return nil, errors.Wrap(err, "could not canonicalize provable document")
	}
	canonicalString := normalized.(string)
	return &canonicalString, nil
}

func (j JWSSignatureSuite) Digest(tbd []byte) ([]byte, error) {
	if j.MessageDigestAlgorithm() != crypto.SHA256 {
		return nil, fmt.Errorf("unexpected digest algorithm: %s", j.MessageDigestAlgorithm().String())
	}
	hash := sha256.Sum256(tbd)
	return hash[:], nil
}

func (j JWSSignatureSuite) CreateVerifyHash(canonicalDoc []byte, proof Proof) ([]byte, error) {
	// marshal proof to prepare for canonicalizaiton
	marshaledOptions, err := j.Marshal(proof)
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
	output, err := j.Digest(canonicalizedOptionsBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not take digest of proof")
	}

	// 4.3 hash the canonicalized doc and append it to the output
	documentDigest, err := j.Digest(canonicalDoc)
	if err != nil {
		return nil, errors.Wrap(err, "could not take digest of provable")
	}
	output = append(output, documentDigest...)

	// 5. return the output
	return output, nil
}

func (j JWSSignatureSuite) createDetachedJWS(alg string, signature []byte) (*string, error) {
	// header is set as per the spec https://w3c-ccg.github.io/lds-jws2020/#json-web-signature-2020
	header := map[string]interface{}{
		"alg":  alg,
		"b64":  false,
		"crit": []string{"b64"},
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	headerStr := base64.RawURLEncoding.EncodeToString(headerBytes)
	signatureStr := base64.RawURLEncoding.EncodeToString(signature)
	detachedJWS := headerStr + ".." + signatureStr
	return &detachedJWS, nil
}

// verifySuiteContext makes sure a given provable document has the @context values this suite requires
func (j JWSSignatureSuite) verifySuiteContext(p Provable) error {
	bytes, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(bytes, &generic); err != nil {
		return err
	}
	context, ok := generic["@context"]
	if !ok {
		return errors.New("no context property found in provable struct")
	}

	// since context can either be a string or an array of strings we need to try both
	strContexts, err := util.InterfaceToStrings(context)
	if err != nil {
		return errors.Wrap(err, "could not stringify contexts")
	}
	for _, requiredContext := range j.RequiredContexts() {
		if !util.Contains(requiredContext, strContexts) {
			return fmt.Errorf("provable does not contain required context: %s", requiredContext)
		}
	}
	return nil
}

type JsonWebSignature2020Proof struct {
	Type               SignatureType `json:"type,omitempty"`
	Created            string        `json:"created,omitempty"`
	JWS                string        `json:"jws,omitempty"`
	ProofPurpose       ProofPurpose  `json:"proofPurpose,omitempty"`
	VerificationMethod string        `json:"verificationMethod,omitempty"`
}

func FromGenericProof(p Proof) (*JsonWebSignature2020Proof, error) {
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
	methodValue, ok := generic["verificationMethod"].(string)
	if !ok {
		methodValue = ""
	}
	return &JsonWebSignature2020Proof{
		Type:               SignatureType(typeValue),
		Created:            createdValue,
		JWS:                jwsValue,
		ProofPurpose:       ProofPurpose(purposeValue),
		VerificationMethod: methodValue,
	}, nil
}

func (j *JsonWebSignature2020Proof) ToGenericProof() Proof {
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

func (j JWSSignatureSuite) createProof(verificationMethod string) JsonWebSignature2020Proof {
	return JsonWebSignature2020Proof{
		Type:               j.SignatureAlgorithm(),
		Created:            util.GetISO8601Timestamp(),
		ProofPurpose:       AssertionMethod,
		VerificationMethod: verificationMethod,
	}
}
