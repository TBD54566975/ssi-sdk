package status

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bitset"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/util"
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
	statusListIndices, err := prepareCredentialsForStatusList(issuedCredentials)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not generate status list credential")
	}

	bitString, err := bitstringGeneration(statusListIndices)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not generate bitstring for status list credential")
	}

	rlc := StatusList2021Credential{
		ID:            id,
		Type:          StatusList2021Type,
		StatusPurpose: purpose,
		EncodedList:   bitString,
	}

	builder := credential.NewVerifiableCredentialBuilder()
	errMsgFragment := "could not generate status list credential: error setting "
	if err := builder.SetID(id); err != nil {
		return nil, util.LoggingErrorMsg(err, errMsgFragment+"id")
	}
	if err := builder.SetIssuer(issuer); err != nil {
		return nil, util.LoggingErrorMsg(err, errMsgFragment+"issuer")
	}
	if err := builder.AddContext(StatusList2021Context); err != nil {
		return nil, util.LoggingErrorMsg(err, errMsgFragment+"context")
	}
	if err := builder.AddType(StatusList2021CreddentialType); err != nil {
		return nil, util.LoggingErrorMsg(err, errMsgFragment+"type")
	}
	rlcJSON, err := util.ToJSONMap(rlc)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not turn RLC to JSON")
	}
	if err := builder.SetCredentialSubject(rlcJSON); err != nil {
		return nil, util.LoggingErrorMsg(err, errMsgFragment+"subject")
	}

	statusListCredential, err := builder.Build()
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not build status list credential")
	}
	return statusListCredential, nil
}

// prepareCredentialsForStatusList does two things
// 1. validates that all credentials are using the StatusList2021 in the credentialStatus property
// 2. assembles a list of `statusListIndex` values for the bitstring generation algorithm
// NOTE: this process does not fail fast, and enumerates all failed credential values
func prepareCredentialsForStatusList(credentials []credential.VerifiableCredential) ([]string, error) {
	var statusListIndices []string

	// make sure there are no duplicate index values
	duplicateCheck := make(map[string]bool)
	var errorResults []string

	for _, cred := range credentials {
		entry, ok := cred.CredentialStatus.(StatusList2021Entry)
		if !ok {
			errorResults = append(errorResults, fmt.Sprintf("credential<%s> not using the StatusList2021 credentialStatus property", cred.ID))
		} else {
			// if a duplicate is found, we have an error
			if _, ok := duplicateCheck[entry.StatusListIndex]; ok {
				errorResults = append(errorResults, fmt.Sprintf("credential<%s> has a duplicate status list index value", cred.ID))
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
		return nil, fmt.Errorf("%d credential(s) were in error: %s", numFailed, strings.Join(errorResults, ","))
	}
	return statusListIndices, nil
}

// https://w3c-ccg.github.io/vc-status-list-2021/#bitstring-generation-algorithm
func bitstringGeneration(statusListCredentialIndices []string) (string, error) {
	if len(statusListCredentialIndices) == 0 {
		return "", errors.New("cannot create a status list bitstring with no credential indices")
	}

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
	if _, err := zw.Write(bitstringBinary); err != nil {
		return "", errors.Wrap(err, "could not compress status list bitstring using GZIP")
	}

	if err := zw.Close(); err != nil {
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

	unzipped, err := ioutil.ReadAll(zr)
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
