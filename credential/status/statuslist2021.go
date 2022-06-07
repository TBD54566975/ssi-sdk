package status

import (
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
	ID                   string        `json:"id" validate:"require"`
	Type                 string        `json:"type" validate:"require"`
	StatusPurpose        StatusPurpose `json:"statusPurpose" validate:"require"`
	StatusListCredential string        `json:"statusListCredential" validate:"require"`
}

// StatusList2021Credential the credential subject value of a status list credential
// https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021credential
type StatusList2021Credential struct {
	ID            string        `json:"id"`
	Type          string        `json:"type"`
	StatusPurpose StatusPurpose `json:"statusPurpose"`
	EncodedList   string        `json:"encodedList"`
}

// GenerateStatusList2021Credential generates a status list credential given an ID (the URI where this entity will
// be hosted), the issuer DID, the purpose of the list, and a set of credentials to include in the list.
// https://w3c-ccg.github.io/vc-status-list-2021/#generate-algorithm
func GenerateStatusList2021Credential(id string, issuer string, purpose StatusPurpose, issuedCredentials []credential.VerifiableCredential) (*credential.VerifiableCredential, error) {
	rlc := StatusList2021Credential{
		ID:            id,
		Type:          StatusList2021Type,
		StatusPurpose: purpose,
		EncodedList:   bitstringGeneration(issuedCredentials),
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

func bitstringGeneration(issuedCredentials []credential.VerifiableCredential) string {
	bits := make([]byte, 16*KB)
	return string(bits)
}
