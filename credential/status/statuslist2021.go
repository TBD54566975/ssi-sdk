package status

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bitset"

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

	rlc := StatusList2021Credential{
		ID:            id,
		Type:          StatusList2021Type,
		StatusPurpose: purpose,
		EncodedList:   bitstringGeneration(statusListIndices),
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
func prepareCredentialsForStatusList(credentials []credential.VerifiableCredential) ([]string, error) {
	// track non-compliant creds for a nice error message
	var failedValues []string
	var statusListIndices []string
	for _, cred := range credentials {
		entry, ok := cred.CredentialStatus.(StatusList2021Entry)
		if !ok {
			failedValues = append(failedValues, cred.ID)
		} else {
			statusListIndices = append(statusListIndices, entry.StatusListIndex)
		}
	}
	numFailed := len(failedValues)
	if numFailed > 0 {
		return nil, fmt.Errorf("%d credential(s) are not using the StatusList2021 credentialStatus property: %s", numFailed, strings.Join(failedValues, ","))
	}
	return statusListIndices, nil
}

// https://w3c-ccg.github.io/vc-status-list-2021/#bitstring-generation-algorithm
func bitstringGeneration(statusListCredentialIndices []string) (string, error) {
	b := bitset.New(16 * KB)
	for _, index := range statusListCredentialIndices {
		indexInt, err := strconv.Atoi(index)
		if indexInt < 0 || err != nil {
			return "", fmt.Errorf("invalid status list index value, not a valid positive integer: %s", index)
		}
		b.Set(uint(indexInt))
	}
	return b.String(), nil
}
