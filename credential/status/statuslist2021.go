package status

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/bits-and-blooms/bitset"
	"github.com/pkg/errors"
)

type StatusPurpose string

const (
	StatusRevocation StatusPurpose = "revocation"
	StatusSuspension StatusPurpose = "suspension"

	StatusList2021CreddentialType string = "StatusList2021Credential"
	StatusList2021EntryType       string = "StatusList2021Entry"
	StatusList2021Type            string = "StatusList2021"

	StatusList2021Context string = "https://w3id.org/vc/status-list/2021/v1"

	// KB represents the size of a KB
	KB = 1 << 10
)

// StatusList2021Entry the representation within a credential that is associated with a status list
// https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021entry
type StatusList2021Entry struct {
	ID                   string        `json:"id" validate:"required"`
	Type                 string        `json:"type" validate:"required"`
	StatusPurpose        StatusPurpose `json:"statusPurpose" validate:"required"`
	StatusListIndex      string        `json:"statusListIndex" validate:"required"`
	StatusListCredential string        `json:"statusListCredential" validate:"required"`
}

// StatusList2021Credential the credential subject value of a status list credential
// https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021credential
type StatusList2021Credential struct {
	ID            string        `json:"id"  validate:"required"`
	Type          string        `json:"type"  validate:"required"`
	StatusPurpose StatusPurpose `json:"statusPurpose"  validate:"required"`
	EncodedList   string        `json:"encodedList"  validate:"required"`
}

// GenerateStatusList2021Credential generates a status list credential given an ID (the URI where this entity will
// be hosted), the issuer DID, the purpose of the list, and a set of credentials to include in the list.
// https://w3c-ccg.github.io/vc-status-list-2021/#generate-algorithm
func GenerateStatusList2021Credential(id string, issuer string, purpose StatusPurpose, issuedCredentials []credential.VerifiableCredential) (*credential.VerifiableCredential, error) {
	statusListIndices, err := prepareCredentialsForStatusList(purpose, issuedCredentials)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate status list credential")
	}

	bitString, err := bitstringGeneration(statusListIndices)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate bitstring for status list credential")
	}

	rlc := StatusList2021Credential{
		ID:            id,
		Type:          StatusList2021Type,
		StatusPurpose: purpose,
		EncodedList:   bitString,
	}

	builder := credential.NewVerifiableCredentialBuilder()
	errMsgFragment := "could not generate status list credential: error setting "
	if err = builder.SetID(id); err != nil {
		return nil, errors.Wrap(err, errMsgFragment+"id")
	}
	if err = builder.SetIssuer(issuer); err != nil {
		return nil, errors.Wrap(err, errMsgFragment+"issuer")
	}
	if err = builder.AddContext(StatusList2021Context); err != nil {
		return nil, errors.Wrap(err, errMsgFragment+"context")
	}
	if err = builder.AddType(StatusList2021CreddentialType); err != nil {
		return nil, errors.Wrap(err, errMsgFragment+"type")
	}
	rlcJSON, err := util.ToJSONMap(rlc)
	if err != nil {
		return nil, errors.Wrap(err, "could not turn RLC to JSON")
	}
	if err = builder.SetCredentialSubject(rlcJSON); err != nil {
		return nil, errors.Wrap(err, errMsgFragment+"subject")
	}

	statusListCredential, err := builder.Build()
	if err != nil {
		return nil, errors.Wrap(err, "could not build status list credential")
	}
	return statusListCredential, nil
}

// prepareCredentialsForStatusList does two things
// 1. validates that all credentials are using the StatusList2021 in the credentialStatus property
// 2. assembles a list of `statusListIndex` values for the bitstring generation algorithm
// NOTE: this process does not fail fast, and enumerates all failed credential values
func prepareCredentialsForStatusList(purpose StatusPurpose, credentials []credential.VerifiableCredential) ([]string, error) {
	var statusListIndices []string

	// make sure there are no duplicate index values
	duplicateCheck := make(map[string]bool)
	var errorResults []string

	for _, cred := range credentials {
		entry, err := getStatusEntry(cred.CredentialStatus)
		if err != nil {
			errorResults = append(errorResults, fmt.Sprintf("credential<%s> not using the StatusList2021 "+
				"credentialStatus property", cred.ID))
		} else {
			// check to see if the purpose matches the credential's purpose
			if entry.StatusPurpose != purpose {
				errorResults = append(errorResults, fmt.Sprintf("credential<%s> has a different status "+
					"purpose<%s> value than the status credential<%s>", cred.ID, entry.StatusPurpose, purpose))
			}

			// if a duplicate is found, we have an error
			if _, ok := duplicateCheck[entry.StatusListIndex]; ok {
				errorResults = append(errorResults, fmt.Sprintf("credential<%s> has a duplicate status list "+
					"index value", cred.ID))
			}
			duplicateCheck[entry.StatusListIndex] = true

			// if we have an error, no need to build this list
			if len(errorResults) == 0 {
				statusListIndices = append(statusListIndices, entry.StatusListIndex)
			}
		}
	}

	numFailed := len(errorResults)
	if numFailed > 0 {
		return nil, fmt.Errorf("%d credential(s) in error: %s", numFailed, strings.Join(errorResults, ","))
	}
	return statusListIndices, nil
}

// determine whether the credential status property is of the expected format
// additionally makes sure the status list has all required properties
func getStatusEntry(maybeCredentialStatus interface{}) (*StatusList2021Entry, error) {
	statusBytes, err := json.Marshal(maybeCredentialStatus)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal credential status property")
	}
	var statusEntry StatusList2021Entry
	if err = json.Unmarshal(statusBytes, &statusEntry); err != nil {
		return nil, errors.Wrap(err, "could not unmarshal credential status property")
	}
	return &statusEntry, util.IsValidStruct(statusEntry)
}

// https://w3c-ccg.github.io/vc-status-list-2021/#bitstring-generation-algorithm
func bitstringGeneration(statusListCredentialIndices []string) (string, error) {
	// check to see there are no duplicate index values
	duplicateCheck := make(map[uint]bool)

	// 1. Let bitstring be a list of bits with a minimum size of 16KB, where each bit is initialized to 0 (zero).
	b := bitset.New(16 * KB)

	// 2. For each bit in bitstring, if there is a corresponding statusListIndex value in a revoked credential in
	// issuedCredentials, set the bit to 1 (one), otherwise set the bit to 0 (zero).
	for _, index := range statusListCredentialIndices {
		indexInt, err := strconv.Atoi(index)
		if indexInt < 0 || err != nil {
			return "", fmt.Errorf("invalid status list index value, not a valid positive integer: %s", index)
		}
		indexValue := uint(indexInt)
		if _, ok := duplicateCheck[indexValue]; ok {
			return "", fmt.Errorf("duplicate status list index value found: %d", indexValue)
		}
		duplicateCheck[indexValue] = true
		b.Set(indexValue)
	}

	bitstringBinary, err := b.MarshalBinary()
	if err != nil {
		return "", errors.Wrap(err, "could not generate bitstring binary representation")
	}

	// 3. Generate a compressed bitstring by using the GZIP compression algorithm [RFC1952] on the bitstring and then
	// base64-encoding [RFC4648] the result.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err = zw.Write(bitstringBinary); err != nil {
		return "", errors.Wrap(err, "could not compress status list bitstring using GZIP")
	}

	if err = zw.Close(); err != nil {
		return "", errors.Wrap(err, "could not close gzip writer")
	}

	base64Bitstring := base64.StdEncoding.EncodeToString(buf.Bytes())

	// 4. Return the compressed bitstring.
	return base64Bitstring, nil
}

// https://w3c-ccg.github.io/vc-status-list-2021/#bitstring-expansion-algorithm
func bitstringExpansion(compressedBitstring string) ([]string, error) {
	// 1. Let compressed bitstring be a compressed status list bitstring.

	// 2. Generate an uncompressed bitstring by using the base64-decoding [RFC4648] algorithm on the compressed
	// bitstring and then expanding the output using the GZIP decompression algorithm [RFC1952].
	decoded, err := base64.StdEncoding.DecodeString(compressedBitstring)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode compressed bitstring")
	}

	bitstringReader := bytes.NewReader(decoded)
	zr, err := gzip.NewReader(bitstringReader)
	if err != nil {
		return nil, errors.Wrap(err, "could not unzip status list bitstring using GZIP")
	}

	unzipped, err := io.ReadAll(zr)
	if err != nil {
		return nil, errors.Wrap(err, "could not expand status list bitstring using GZIP")
	}

	if err := zr.Close(); err != nil {
		return nil, errors.Wrap(err, "could not close gzip reader")
	}

	b := bitset.New(uint(len(unzipped)))
	if err := b.UnmarshalBinary(unzipped); err != nil {
		return nil, errors.Wrap(err, "could not unmarshal binary bitstring")
	}

	// find set bits to reconstruct the status list indices
	var expanded []string
	var i uint
	for i = 0; i < b.Len(); i++ {
		if b.Test(i) {
			expanded = append(expanded, strconv.Itoa(int(i)))
		}
	}
	return expanded, nil
}

// ValidateCredentialInStatusList determines whether a credential is contained in a status list 2021 credential
// https://w3c-ccg.github.io/vc-status-list-2021/#validate-algorithm
// NOTE: this method does not perform credential signature/proof block verification
func ValidateCredentialInStatusList(credentialToValidate credential.VerifiableCredential, statusCredential credential.VerifiableCredential) (bool, error) {
	// 1. Let credentialToValidate be a verifiable credentials containing a credentialStatus entry that is a StatusList2021Entry.
	statusListEntryValue, ok := toStatusList2021Entry(credentialToValidate.CredentialStatus)
	if !ok {
		return false, fmt.Errorf("credential to validate<%s> not using the StatusList2021 credentialStatus "+
			"property", credentialToValidate.ID)
	}

	// 2. Let status purpose be the value of statusPurpose in the credentialStatus entry in the credentialToValidate.
	statusPurpose := statusListEntryValue.StatusPurpose

	// 3. Verify all proofs associated with the credentialToValidate. If a proof fails, return a validation error.
	// NOTE: this step is assumed to be done *external* to this method call

	// 4. Verify that the status purpose matches the statusPurpose value in the statusListCredential.
	var statusCredentialValue StatusList2021Credential
	subjectBytes, err := json.Marshal(statusCredential.CredentialSubject)
	if err != nil {
		return false, errors.Wrapf(err, "could not marshal status credential<%s> subject value", statusCredential.ID)
	}
	if err = json.Unmarshal(subjectBytes, &statusCredentialValue); err != nil {
		return false, errors.Wrapf(err, "could not unmarshal status credential<%s> subject value into "+
			"StatusList2021Credential", statusCredential.ID)
	}
	if err = util.IsValidStruct(statusCredentialValue); err != nil {
		return false, errors.Wrapf(err, "credential<%s> is not a valid status credential", statusCredential.ID)
	}
	if statusPurpose != statusCredentialValue.StatusPurpose {
		return false, fmt.Errorf("purpose of credential to validate<%s>: %s, did not match purpose of status "+
			"credential<%s>: %s", credentialToValidate.ID, statusPurpose, statusCredential.ID, statusCredentialValue.StatusPurpose)
	}

	// 5. Let compressed bitstring be the value of the encodedList property of the StatusList2021Credential.
	compressedBitstring := statusCredentialValue.EncodedList

	// 6. Let credentialIndex be the value of the statusListIndex property of the StatusList2021Entry.
	credentialIndex := statusListEntryValue.StatusListIndex

	// 7. Generate a revocation bitstring by passing compressed bitstring to the Bitstring Expansion Algorithm.
	expandedValues, err := bitstringExpansion(compressedBitstring)
	if err != nil {
		return false, errors.Wrapf(err, "could not expand compressed bitstring of status credential<%s>", statusCredential.ID)
	}

	// 8. Let status be the value of the bit at position credentialIndex in the revocation bitstring.
	// 9. Return true if status is 1, false otherwise.
	for _, idx := range expandedValues {
		if idx == credentialIndex {
			return true, nil
		}
	}
	return false, nil
}

func toStatusList2021Entry(credStatus interface{}) (*StatusList2021Entry, bool) {
	statusListEntryValue, ok := credStatus.(StatusList2021Entry)
	if ok {
		return &statusListEntryValue, true
	}

	credStatusMap, ok := credStatus.(map[string]interface{})
	if !ok {
		return nil, false
	}

	statusListEntry := StatusList2021Entry{
		ID:                   credStatusMap["id"].(string),
		Type:                 credStatusMap["type"].(string),
		StatusPurpose:        StatusPurpose(credStatusMap["statusPurpose"].(string)),
		StatusListIndex:      credStatusMap["statusListIndex"].(string),
		StatusListCredential: credStatusMap["statusListCredential"].(string),
	}

	return &statusListEntry, true
}
