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

var _ CryptoSuiteInfo = (*BBSPlusSignatureSuite)(nil)

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
	// create proof before running the create verify hash algorithm
	// TODO(gabe) support required reveal values
	proof := b.createProof(s.GetKeyID(), s.GetProofPurpose(), nil)

	// prepare proof options
	contexts, err := GetContextsFromProvable(p)
	if err != nil {
		return errors.Wrap(err, "getting contexts from provable")
	}

	// make sure the suite's context(s) are included
	contexts = ensureRequiredContexts(contexts, b.RequiredContexts())
	opts := &ProofOptions{Contexts: contexts}

	// 3. tbs value as a result of create verify hash
	var genericProvable map[string]interface{}
	pBytes, err := json.Marshal(p)
	if err != nil {
		return errors.Wrap(err, "marshaling provable")
	}
	if err = json.Unmarshal(pBytes, &genericProvable); err != nil {
		return errors.Wrap(err, "unmarshaling provable")
	}
	tbs, err := b.CreateVerifyHash(genericProvable, proof, opts)
	if err != nil {
		return errors.Wrap(err, "running create verify hash algorithm")
	}

	// 4 & 5. create the signature over the provable data as a BBS+ signature
	proofValue, err := s.Sign(tbs)
	if err != nil {
		return errors.Wrap(err, "signing provable value")
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

	// must make sure there is no proof value before signing/verifying
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
		return errors.Wrap(err, "coercing proof into BBSPlusSignature2020Proof proof")
	}

	// remove proof before verifying
	p.SetProof(nil)

	// make sure we set it back after we're done verifying
	defer p.SetProof(proof)

	// remove the proof value in the proof before verification
	signatureValue, err := decodeProofValue(gotProof.ProofValue)
	if err != nil {
		return errors.Wrap(err, "decoding proof value")
	}
	gotProof.SetProofValue("")

	// prepare proof options
	contexts, err := GetContextsFromProvable(p)
	if err != nil {
		return errors.Wrap(err, "getting contexts from provable")
	}

	// make sure the suite's context(s) are included
	contexts = ensureRequiredContexts(contexts, b.RequiredContexts())
	opts := &ProofOptions{Contexts: contexts}

	// run the create verify hash algorithm on both provable and the proof
	var genericProvable map[string]interface{}
	pBytes, err := json.Marshal(p)
	if err != nil {
		return errors.Wrap(err, "marshaling provable")
	}
	if err = json.Unmarshal(pBytes, &genericProvable); err != nil {
		return errors.Wrap(err, "unmarshaling provable")
	}
	tbv, err := b.CreateVerifyHash(genericProvable, gotProof, opts)
	if err != nil {
		return errors.Wrap(err, "running create verify hash algorithm")
	}

	if err = v.Verify(tbv, signatureValue); err != nil {
		return errors.Wrap(err, "verifying BBS+ signature")
	}
	return nil
}

// decodeProofValue because the proof could have been encoded in a variety of manners we must try them all
// https://github.com/w3c-ccg/ldp-bbs2020/issues/16#issuecomment-1436148820
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

var _ CryptoSuiteProofType = (*BBSPlusSignatureSuite)(nil)

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
		return nil, errors.Wrap(err, "ld normalizing")
	}
	canonicalString := normalized.(string)
	return &canonicalString, nil
}

// CreateVerifyHash https://w3c-ccg.github.io/data-integrity-spec/#create-verify-hash-algorithm
// augmented by https://w3c-ccg.github.io/ldp-bbs2020/#create-verify-data-algorithm
func (b BBSPlusSignatureSuite) CreateVerifyHash(doc map[string]interface{}, proof crypto.Proof, opts *ProofOptions) ([]byte, error) {
	// first, make sure "created" exists in the proof and insert an LD context property for the proof vocabulary
	preparedProof, err := b.prepareProof(proof, opts)
	if err != nil {
		return nil, errors.Wrap(err, "preparing proof for the create verify hash algorithm")
	}

	// marshal doc to prepare for canonicalizaiton
	marshaledProvable, err := b.Marshal(doc)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling doc")
	}

	// canonicalize doc using the suite's method
	canonicalProvable, err := b.Canonicalize(marshaledProvable)
	if err != nil {
		return nil, errors.Wrap(err, "canonicalizing doc")
	}

	// marshal proof to prepare for canonicalizaiton
	marshaledOptions, err := b.Marshal(preparedProof)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling proof")
	}

	// 4.1 canonicalize  proof using the suite's method
	canonicalizedOptions, err := b.Canonicalize(marshaledOptions)
	if err != nil {
		return nil, errors.Wrap(err, "canonicalizing proof")
	}

	// 4.2 set output to the result of the hash of the canonicalized options document
	canonicalizedOptionsBytes := []byte(*canonicalizedOptions)
	optionsDigest, err := b.Digest(canonicalizedOptionsBytes)
	if err != nil {
		return nil, errors.Wrap(err, "taking digest of proof")
	}

	// 4.3 hash the canonicalized doc and append it to the output
	canonicalDoc := []byte(*canonicalProvable)
	documentDigest, err := b.Digest(canonicalDoc)
	if err != nil {
		return nil, errors.Wrap(err, "taking digest of doc")
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

// BBSPlusProofFromGenericProof accepts either a slice with exactly one element, or a single element and creates a
// BBSPlusProofFromGenericProof by unmarshaling the JSON marshaled representation of the element found in `p`.
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
	var result BBSPlusSignature2020Proof
	if err = json.Unmarshal(proofBytes, &result); err != nil {
		return nil, err
	}
	
	return &result, nil
}
