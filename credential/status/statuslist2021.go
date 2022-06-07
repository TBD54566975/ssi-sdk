package status

type StatusPurpose string

const (
	StatusRevocation StatusPurpose = "revocation"
	StatusSuspension StatusPurpose = "suspension"

	StatusList2021EntryType string = "StatusList2021Entry"
	StatusList2021Type      string = "StatusList2021"
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
