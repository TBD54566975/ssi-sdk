package cryptosuite

import (
	gocrypto "crypto"
	"encoding/base64"
	"strings"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	. "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

const (
	BBSPlusSignatureProof2020 SignatureType = "BbsBlsSignatureProof2020"
)

type BBSPlusSignatureProofSuite struct {
	CryptoSuiteProofType
}

func GetBBSPlusSignatureProofSuite() *BBSPlusSignatureProofSuite {
	return new(BBSPlusSignatureProofSuite)
}

// CryptoSuiteInfo interface

var _ CryptoSuiteInfo = (*BBSPlusSignatureProofSuite)(nil)

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
	return BBSPlusSignatureProof2020
}

func (BBSPlusSignatureProofSuite) RequiredContexts() []string {
	return []string{BBSSecurityContext}
}

// SelectivelyDisclose takes in a credential and  a map of fields to disclose as an LD frame
func (b BBSPlusSignatureProofSuite) SelectivelyDisclose(v BBSPlusVerifier, p Provable, toDiscloseFrame map[string]interface{}, nonce []byte) (map[string]interface{}, error) {
	// first compact the document with the security context
	compactProvable, compactProof, err := b.compactProvable(p)
	if err != nil {
		return nil, err
	}

	deriveProofResult, err := b.CreateDeriveProof(compactProvable, toDiscloseFrame)
	if err != nil {
		return nil, err
	}

	bbsPlusProof, err := BBSPlusProofFromGenericProof(compactProof)
	if err != nil {
		return nil, err
	}

	// prepare the statements and indicies to be revealed
	statements, revealIndicies, err := b.prepareRevealData(*deriveProofResult, *bbsPlusProof)
	if err != nil {
		return nil, err
	}

	// pull of signature from original provable
	signatureBytes, err := decodeProofValue(bbsPlusProof.ProofValue)
	if err != nil {
		return nil, err
	}

	// derive the proof
	derivedProofValue, err := v.DeriveProof(statements, signatureBytes, nonce, revealIndicies)
	if err != nil {
		return nil, err
	}

	// attach the proof to the derived credential
	derivedProof := &BBSPlusSignature2020Proof{
		Type:               BBSPlusSignatureProof2020,
		Created:            bbsPlusProof.Created,
		VerificationMethod: bbsPlusProof.VerificationMethod,
		ProofPurpose:       bbsPlusProof.ProofPurpose,
		ProofValue:         base64.StdEncoding.EncodeToString(derivedProofValue),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
	}
	derivedCred := deriveProofResult.RevealedDocument
	derivedCred["proof"] = derivedProof
	return derivedCred, nil
}

func (BBSPlusSignatureProofSuite) compactProvable(p Provable) (Provable, *crypto.Proof, error) {
	var genericProvable map[string]interface{}
	provableBytes, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	if err = json.Unmarshal(provableBytes, &genericProvable); err != nil {
		return nil, nil, errors.Wrap(err, "failed to unmarshal provable to generic map")
	}
	compactProvable, err := LDCompact(genericProvable, W3CSecurityContext)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to compact provable")
	}

	// create a copy of the proof and remove it from the provable
	compactProof := crypto.Proof(compactProvable["proof"])
	delete(compactProvable, "proof")

	// turn the compact provable back to a generic credential
	compactedProvableBytes, err := json.Marshal(compactProvable)
	if err != nil {
		return nil, nil, err
	}
	var genericCred credential.GenericCredential
	if err = json.Unmarshal(compactedProvableBytes, &genericCred); err != nil {
		return nil, nil, errors.Wrap(err, "failed to unmarshal compacted provable to generic credential")
	}
	return &genericCred, &compactProof, nil
}

func (b BBSPlusSignatureProofSuite) prepareRevealData(deriveProofResult DeriveProofResult, bbsPlusProof BBSPlusSignature2020Proof) (statementBytesArrays [][]byte, revealIndices []int, err error) {
	// prepare proof by removing the proof value and canonicalizing
	canonicalProofStatements, err := b.prepareBLSProof(bbsPlusProof)
	if err != nil {
		return nil, nil, err
	}

	// total # indicies to be revealed = total statements in the proof - original proof result + revealed indicies
	numProofStatements := len(canonicalProofStatements)
	revealIndices = make([]int, numProofStatements+len(deriveProofResult.RevealedIndicies))

	// add the original proof result to the beginning of the reveal indicies
	for i := range canonicalProofStatements {
		revealIndices[i] = i
	}

	// add the other statements to the indicies
	for i := range deriveProofResult.RevealedIndicies {
		revealIndices[i+numProofStatements] = numProofStatements + deriveProofResult.RevealedIndicies[i]
	}

	// turn all statements into bytes before signing
	statements := append(canonicalProofStatements, deriveProofResult.InputProofDocumentStatements...)
	statementBytesArrays = make([][]byte, len(statements))
	for i := range statements {
		statementBytesArrays[i] = []byte(statements[i])
	}
	return statementBytesArrays, revealIndices, nil
}

func (b BBSPlusSignatureProofSuite) prepareBLSProof(bbsPlusProof BBSPlusSignature2020Proof) ([]string, error) {
	// canonicalize proof after removing the proof value
	bbsPlusProof.SetProofValue("")

	marshaledProof, err := b.Marshal(bbsPlusProof)
	if err != nil {
		return nil, err
	}

	// add the security context before canonicalization
	var genericProof map[string]interface{}
	if err = json.Unmarshal(marshaledProof, &genericProof); err != nil {
		return nil, err
	}
	genericProof["@context"] = W3CSecurityContext

	proofBytes, err := json.Marshal(genericProof)
	if err != nil {
		return nil, err
	}

	canonicalProof, err := b.Canonicalize(proofBytes)
	if err != nil {
		return nil, err
	}
	return canonicalizedLDToStatements(*canonicalProof), nil
}

type DeriveProofResult struct {
	RevealedIndicies             []int
	InputProofDocumentStatements []string
	RevealedDocument             map[string]interface{}
}

// CreateDeriveProof https://w3c-ccg.github.io/ldp-bbs2020/#create-derive-proof-data-algorithm
func (b BBSPlusSignatureProofSuite) CreateDeriveProof(inputProofDocument Provable, revealDocument map[string]interface{}) (*DeriveProofResult, error) {
	// 1. Apply the canonicalization algorithm to the input proof document to obtain a set of statements represented
	// as n-quads. Let this set be known as the input proof document statements.
	marshaledInputProofDoc, err := b.Marshal(inputProofDocument)
	if err != nil {
		return nil, err
	}
	inputProofDocumentStatements, err := b.Canonicalize(marshaledInputProofDoc)
	if err != nil {
		return nil, err
	}

	// 2. Record the total number of statements in the input proof document statements.
	// Let this be known as the total statements.
	statements := canonicalizedLDToStatements(*inputProofDocumentStatements)
	totalStatements := len(statements)

	// 3. Apply the framing algorithm to the input proof document.
	// Let the product of the framing algorithm be known as the revealed document.
	revealedDocument, err := LDFrame(inputProofDocument, revealDocument)
	if err != nil {
		return nil, err
	}

	// 4. Canonicalize the revealed document using the canonicalization algorithm to obtain the set of statements
	// represented as n-quads. Let these be known as the revealed statements.
	marshaledRevealedDocument, err := b.Marshal(revealedDocument)
	if err != nil {
		return nil, err
	}
	canonicalRevealedStatements, err := b.Canonicalize(marshaledRevealedDocument)
	if err != nil {
		return nil, err
	}
	revealedStatements := canonicalizedLDToStatements(*canonicalRevealedStatements)

	// 5. Initialize an empty array of length equal to the number of revealed statements.
	// Let this be known as the revealed indicies array.
	revealedIndicies := make([]int, len(revealedStatements))

	// 6. For each statement in order:
	// 6.1 Find the numerical index the statement occupies in the set input proof document statements.
	// 6.2. Insert this numerical index into the revealed indicies array

	// create an index of all statements in the original doc
	documentStatementsMap := make(map[string]int, totalStatements)
	for i, statement := range statements {
		documentStatementsMap[statement] = i
	}

	// find index of each revealed statement in the original doc
	for i := range revealedStatements {
		statement := revealedStatements[i]
		statementIndex := documentStatementsMap[statement]
		revealedIndicies[i] = statementIndex
	}

	return &DeriveProofResult{
		RevealedIndicies:             revealedIndicies,
		InputProofDocumentStatements: statements,
		RevealedDocument:             revealedDocument.(map[string]interface{}),
	}, nil
}

// Verify verifies a BBS Plus derived proof. Bug here: https://github.com/w3c-ccg/ldp-bbs2020/issues/62
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

	bbsPlusVerifier, ok := v.(*BBSPlusVerifier)
	if !ok {
		return errors.New("verifier does not implement BBSPlusVerifier")
	}

	nonce, err := base64.StdEncoding.DecodeString(gotProof.Nonce)
	if err != nil {
		return errors.Wrap(err, "could not decode nonce")
	}
	if err = bbsPlusVerifier.VerifyDerived(tbv, signatureValue, nonce); err != nil {
		return errors.Wrap(err, "could not verify BBS+ signature")
	}
	return nil
}

// CryptoSuiteProofType interface

var _ CryptoSuiteProofType = (*BBSPlusSignatureProofSuite)(nil)

func (BBSPlusSignatureProofSuite) Marshal(data interface{}) ([]byte, error) {
	// JSONify the provable object
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

func (BBSPlusSignatureProofSuite) Canonicalize(marshaled []byte) (*string, error) {
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

func canonicalizedLDToStatements(canonicalized string) []string {
	lines := strings.Split(canonicalized, "\n")
	res := make([]string, 0, len(lines))
	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			res = append(res, lines[i])
		}
	}
	return res
}

// CreateVerifyHash https://w3c-ccg.github.io/data-integrity-spec/#create-verify-hash-algorithm
// augmented by https://w3c-ccg.github.io/ldp-bbs2020/#create-verify-data-algorithm
func (b BBSPlusSignatureProofSuite) CreateVerifyHash(provable Provable, proof crypto.Proof, opts *ProofOptions) ([]byte, error) {
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

func (b BBSPlusSignatureProofSuite) prepareProof(proof crypto.Proof, opts *ProofOptions) (*crypto.Proof, error) {
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}

	var genericProof map[string]interface{}
	if err = json.Unmarshal(proofBytes, &genericProof); err != nil {
		return nil, err
	}

	// proof cannot have a proof value or nonce
	delete(genericProof, "proofValue")
	delete(genericProof, "nonce")

	// make sure the proof has a timestamp
	created, ok := genericProof["created"]
	if !ok || created == "" {
		genericProof["created"] = GetRFC3339Timestamp()
	}

	// for verification, we must replace the BBS ProofType with the Signature Type
	genericProof["type"] = BBSPlusSignature2020

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

func (BBSPlusSignatureProofSuite) Digest(tbd []byte) ([]byte, error) {
	// handled by the algorithm itself
	return tbd, nil
}
