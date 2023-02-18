package cryptosuite

import (
	gocrypto "crypto"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
	. "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

type BBSPlusSignatureProofSuite struct {
	CryptoSuiteProofType
}

func GetBBSPlusSignatureProofSuite() CryptoSuite {
	return new(BBSPlusSignatureProofSuite)
}

// CryptoSuiteInfo interface

func (BBSPlusSignatureProofSuite) ID() string {
	return BBSPlusSignatureSuiteID
}

func (BBSPlusSignatureProofSuite) Type() LDKeyType {
	return BBSPlusSignatureSuiteType
}

func (BBSPlusSignatureProofSuite) CanonicalizationAlgorithm() string {
	return BBSPlusSignatureSuiteCanonicalizationAlgorithm
}

func (BBSPlusSignatureProofSuite) MessageDigestAlgorithm() gocrypto.Hash {
	return BBSPlusSignatureSuiteDigestAlgorithm
}

func (BBSPlusSignatureProofSuite) SignatureAlgorithm() SignatureType {
	return BBSPlusSignatureSuiteProofAlgorithm
}

func (BBSPlusSignatureProofSuite) RequiredContexts() []string {
	return []string{BBSSecurityContext}
}

func (b BBSPlusSignatureProofSuite) Sign(s Signer, p Provable) error {
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
	proof.SetProofValue(string(proofValue))
	genericProof := crypto.Proof(proof)
	p.SetProof(&genericProof)
	return nil
}

func (b BBSPlusSignatureProofSuite) prepareProof(proof crypto.Proof, opts *ProofOptions) (*crypto.Proof, error) {
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}

	var genericProof map[string]any
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

	var contexts []any
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

func (b BBSPlusSignatureProofSuite) Verify(v Verifier, p Provable) error {
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
	jwsCopy := []byte(gotProof.ProofValue)
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

	if err = v.Verify(jwsCopy, tbv); err != nil {
		return errors.Wrap(err, "could not verify BBS+ signature")
	}
	return nil
}

// CryptoSuiteProofType interface

func (BBSPlusSignatureProofSuite) Marshal(data any) ([]byte, error) {
	// JSONify the provable object
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

func (BBSPlusSignatureProofSuite) Canonicalize(marshaled []byte) (*string, error) {
	// the LD library anticipates a generic golang json object to normalize
	var generic map[string]any
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
func (b BBSPlusSignatureProofSuite) CreateVerifyHash(provable Provable, _ crypto.Proof, _ *ProofOptions) ([]byte, error) {
	// marshal provable to prepare for canonicalizaiton
	marshaledProvable, err := b.Marshal(provable)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal provable")
	}

	// 1.Canonicalize the input document using the canonicalization algorithm
	// to a set of statements represented as n-quads.
	canonicalProvable, err := b.Canonicalize(marshaledProvable)
	if err != nil {
		return nil, errors.Wrap(err, "could not canonicalize provable")
	}

	// 2. Initialize an empty array of length equal to the number of statements,
	// let this be known as the statement digests array.
	statements := canonicalizedProvableToStatements(*canonicalProvable)
	statementDigestsArray := make([]string, len(statements))

	// 3. For each statement in order:
	// 3.1 Apply the statement digest algorithm to obtain a statement digest
	// 3.2 Insert the statement digest into the statement digests array which
	// MUST maintain same order as the order of the statements returned from the canonicalization algorithm.
	for _, statement := range statements {
		statementDigest, err := b.Digest([]byte(statement))
		if err != nil {
			return nil, errors.Wrap(err, "could not take digest of statement")
		}
		statementDigestsArray = append(statementDigestsArray, string(statementDigest))
	}

	bbsCVHBytes, err := json.Marshal(statementDigestsArray)
	if err != nil {
		return nil, err
	}
	return bbsCVHBytes, nil
}

type bbsCVH struct {
	statementDigestsArray []string
}

func canonicalizedProvableToStatements(canonicalized string) []string {
	lines := strings.Split(canonicalized, "\n")
	res := make([]string, 0, len(lines))
	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			res = append(res, lines[i])
		}
	}
	return res
}

func (b BBSPlusSignatureProofSuite) Digest(tbd []byte) ([]byte, error) {
	if b.MessageDigestAlgorithm() != gocrypto.BLAKE2b_384 {
		return nil, fmt.Errorf("unexpected digest algorithm: %s", b.MessageDigestAlgorithm().String())
	}
	return gocrypto.BLAKE2b_384.New().Sum(tbd), nil
}

func (b BBSPlusSignatureProofSuite) createProof(verificationMethod string, purpose ProofPurpose, requiredRevealStatements []int) BBSPlusSignature2020Proof {
	return BBSPlusSignature2020Proof{
		Type:                     b.SignatureAlgorithm(),
		Created:                  GetRFC3339Timestamp(),
		VerificationMethod:       verificationMethod,
		ProofPurpose:             purpose,
		RequiredRevealStatements: requiredRevealStatements,
	}
}
