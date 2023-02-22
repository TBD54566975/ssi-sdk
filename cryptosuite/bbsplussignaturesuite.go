package cryptosuite

import (
	gocrypto "crypto"
	"encoding/base64"

	"github.com/TBD54566975/ssi-sdk/crypto"
	. "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

const (
	BBSSecurityContext                             string        = "https://w3id.org/security/bbs/v1"
	BBSPlusSignature2020                           SignatureType = "BbsBlsSignature2020"
	BBSPlusSignatureSuiteID                        string        = "https://w3c-ccg.github.io/ldp-bbs2020/#the-bbs-signature-suite-2020"
	BBSPlusSignatureSuiteType                      LDKeyType     = BLS12381G2Key2020
	BBSPlusSignatureSuiteCanonicalizationAlgorithm string        = "https://w3id.org/security#URDNA2015"
	// BBSPlusSignatureSuiteDigestAlgorithm uses https://www.rfc-editor.org/rfc/rfc4634
	BBSPlusSignatureSuiteDigestAlgorithm gocrypto.Hash = gocrypto.BLAKE2b_384
	// BBSPlusSignatureSuiteProofAlgorithm  uses https://www.rfc-editor.org/rfc/rfc7797
)

type BBSPlusSignatureSuite struct {
	CryptoSuiteProofType
}

func GetBBSPlusSignatureSuite() CryptoSuite {
	return new(BBSPlusSignatureSuite)
}

// CryptoSuiteInfo interface

func (BBSPlusSignatureSuite) ID() string {
	return BBSPlusSignatureSuiteID
}

func (BBSPlusSignatureSuite) Type() LDKeyType {
	return BBSPlusSignatureSuiteType
}

func (BBSPlusSignatureSuite) CanonicalizationAlgorithm() string {
	return BBSPlusSignatureSuiteCanonicalizationAlgorithm
}

func (BBSPlusSignatureSuite) MessageDigestAlgorithm() gocrypto.Hash {
	return BBSPlusSignatureSuiteDigestAlgorithm
}

func (BBSPlusSignatureSuite) SignatureAlgorithm() SignatureType {
	return BBSPlusSignature2020
}

func (BBSPlusSignatureSuite) RequiredContexts() []string {
	return []string{BBSSecurityContext}
}

func (b BBSPlusSignatureSuite) Sign(s Signer, p Provable) error {
	// create proof before CVH
	// TODO(gabe) support required reveal values
	proof := b.createProof(s.GetKeyID(), s.GetProofPurpose(), nil)

	// prepare proof options
	contexts, err := GetContextsFromProvable(p)
	if err != nil {
		return errors.Wrap(err, "could not get contexts from provable")
	}

	// make sure the suite's context(s) are included
	contexts = ensureRequiredContexts(contexts, b.RequiredContexts())
	opts := &ProofOptions{Contexts: contexts}

	// 3. tbs value as a result of cvh
	tbs, err := b.CreateVerifyHash(p, proof, opts)
	if err != nil {
		return errors.Wrap(err, "create verify hash algorithm failed")
	}

	// 4 & 5. create the signature over the provable data as a JWS
	proofValue, err := s.Sign(tbs)
	if err != nil {
		return errors.Wrap(err, "could not sign provable value")
	}

	// set the signature on the proof object and return
	proof.SetProofValue(base64.RawStdEncoding.EncodeToString(proofValue))
	genericProof := crypto.Proof(proof)
	p.SetProof(&genericProof)
	return nil
}

func (b BBSPlusSignatureSuite) prepareProof(proof crypto.Proof, opts *ProofOptions) (*crypto.Proof, error) {
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}

	var genericProof map[string]interface{}
	if err = json.Unmarshal(proofBytes, &genericProof); err != nil {
		return nil, err
	}

	// proof cannot have a proof value
	delete(genericProof, "proofValue")

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
		contexts = ArrayStrToInterface(b.RequiredContexts())
	}
	genericProof["@context"] = contexts
	p := crypto.Proof(genericProof)
	return &p, nil
}

func (b BBSPlusSignatureSuite) Verify(v Verifier, p Provable) error {
	proof := p.GetProof()
	gotProof, err := BBSPlusProofFromGenericProof(*proof)
	if err != nil {
		return errors.Wrap(err, "could not prepare proof for verification; error coercing proof into BBSPlusSignature2020Proof proof")
	}

	// remove proof before verifying
	p.SetProof(nil)

	// make sure we set it back after we're done verifying
	defer p.SetProof(proof)

	// remove the proof value in the proof before verification
	signatureValue, err := decodeProofValue(gotProof.ProofValue)
	if err != nil {
		return errors.Wrap(err, "could not decode proof value")
	}
	gotProof.SetProofValue("")

	// prepare proof options
	contexts, err := GetContextsFromProvable(p)
	if err != nil {
		return errors.Wrap(err, "could not get contexts from provable")
	}

	// make sure the suite's context(s) are included
	contexts = ensureRequiredContexts(contexts, b.RequiredContexts())
	opts := &ProofOptions{Contexts: contexts}

	// run CVH on both provable and the proof
	tbv, err := b.CreateVerifyHash(p, gotProof, opts)
	if err != nil {
		return errors.Wrap(err, "create verify hash algorithm failed")
	}

	if err = v.Verify(tbv, signatureValue); err != nil {
		return errors.Wrap(err, "could not verify BBS+ signature")
	}
	return nil
}

// decodeProofValue because the proof could have been encoded in a variety of manners we must try them all
func decodeProofValue(proofValue string) ([]byte, error) {
	signatureBytes, err := base64.RawStdEncoding.DecodeString(proofValue)
	if err == nil {
		return signatureBytes, nil
	}
	signatureBytes, err = base64.StdEncoding.DecodeString(proofValue)
	if err == nil {
		return signatureBytes, nil
	}
	return nil, errors.New("unknown encoding of proof value")
}

// CryptoSuiteProofType interface

func (BBSPlusSignatureSuite) Marshal(data interface{}) ([]byte, error) {
	// JSONify the provable object
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

func (BBSPlusSignatureSuite) Canonicalize(marshaled []byte) (*string, error) {
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

// CreateVerifyHash https://w3c-ccg.github.io/data-integrity-spec/#create-verify-hash-algorithm
// augmented by https://w3c-ccg.github.io/ldp-bbs2020/#create-verify-data-algorithm
func (b BBSPlusSignatureSuite) CreateVerifyHash(provable Provable, proof crypto.Proof, opts *ProofOptions) ([]byte, error) {
	// first, make sure "created" exists in the proof and insert an LD context property for the proof vocabulary
	preparedProof, err := b.prepareProof(proof, opts)
	if err != nil {
		return nil, errors.Wrap(err, "could not prepare proof for the create verify hash algorithm")
	}

	// marshal provable to prepare for canonicalizaiton
	marshaledProvable, err := b.Marshal(provable)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal provable")
	}

	// canonicalize provable using the suite's method
	canonicalProvable, err := b.Canonicalize(marshaledProvable)
	if err != nil {
		return nil, errors.Wrap(err, "could not canonicalize provable")
	}

	// marshal proof to prepare for canonicalizaiton
	marshaledOptions, err := b.Marshal(preparedProof)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal proof")
	}

	// 4.1 canonicalize  proof using the suite's method
	canonicalizedOptions, err := b.Canonicalize(marshaledOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not canonicalize proof")
	}

	// 4.2 set output to the result of the hash of the canonicalized options document
	canonicalizedOptionsBytes := []byte(*canonicalizedOptions)
	optionsDigest, err := b.Digest(canonicalizedOptionsBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not take digest of proof")
	}

	// 4.3 hash the canonicalized doc and append it to the output
	canonicalDoc := []byte(*canonicalProvable)
	documentDigest, err := b.Digest(canonicalDoc)
	if err != nil {
		return nil, errors.Wrap(err, "could not take digest of provable")
	}

	// 5. return the output
	output := append(optionsDigest, documentDigest...)
	return output, nil
}

func (BBSPlusSignatureSuite) Digest(tbd []byte) ([]byte, error) {
	// handled by the algorithm itself
	return tbd, nil
}

func (b BBSPlusSignatureSuite) createProof(verificationMethod string, purpose ProofPurpose, requiredRevealStatements []int) BBSPlusSignature2020Proof {
	return BBSPlusSignature2020Proof{
		Type:                     b.SignatureAlgorithm(),
		Created:                  GetRFC3339Timestamp(),
		VerificationMethod:       verificationMethod,
		ProofPurpose:             purpose,
		RequiredRevealStatements: requiredRevealStatements,
	}
}

type BBSPlusSignature2020Proof struct {
	Type                     SignatureType `json:"type,omitempty"`
	Created                  string        `json:"created,omitempty"`
	VerificationMethod       string        `json:"verificationMethod,omitempty"`
	ProofPurpose             ProofPurpose  `json:"proofPurpose,omitempty"`
	ProofValue               string        `json:"proofValue,omitempty"`
	Nonce                    string        `json:"nonce,omitempty"`
	RequiredRevealStatements []int         `json:"requiredRevealStatements,omitempty"`
}

func (b *BBSPlusSignature2020Proof) SetProofValue(proofValue string) {
	b.ProofValue = proofValue
}

func (b *BBSPlusSignature2020Proof) ToGenericProof() (crypto.Proof, error) {
	proofBytes, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	var genericProof crypto.Proof
	if err = json.Unmarshal(proofBytes, &genericProof); err != nil {
		return nil, err
	}
	return genericProof, nil
}

func BBSPlusProofFromGenericProof(p crypto.Proof) (*BBSPlusSignature2020Proof, error) {
	// check if the proof is an array
	if proofArray, ok := p.([]interface{}); ok {
		if len(proofArray) == 0 {
			return nil, errors.New("expected at least one proof")
		}
		if len(proofArray) > 1 {
			return nil, errors.New("expected only one proof")
		}
		p = proofArray[0]
	}

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
	methodValue, ok := generic["verificationMethod"].(string)
	if !ok {
		methodValue = ""
	}
	purposeValue, ok := generic["proofPurpose"].(string)
	if !ok {
		purposeValue = ""
	}
	proofValue, ok := generic["proofValue"].(string)
	if !ok {
		proofValue = ""
	}
	nonce, ok := generic["nonce"].(string)
	if !ok {
		nonce = ""
	}
	requiredRevealStatements, ok := generic["requiredRevealStatements"].([]int)
	if !ok {
		requiredRevealStatements = nil
	}
	return &BBSPlusSignature2020Proof{
		Type:                     SignatureType(typeValue),
		Created:                  createdValue,
		VerificationMethod:       methodValue,
		ProofPurpose:             ProofPurpose(purposeValue),
		ProofValue:               proofValue,
		Nonce:                    nonce,
		RequiredRevealStatements: requiredRevealStatements,
	}, nil
}
