package status

import (
	"sort"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/credential"
)

func TestGenerateStatusList2021Credential(t *testing.T) {
	t.Run("happy path generation", func(tt *testing.T) {
		revocationID := "revocation-id"
		testIssuer := "test-issuer"
		testCred1 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-1",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "123",
				StatusListCredential: "test-cred",
			},
		}
		testCred2 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-2",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "124",
				StatusListCredential: "test-cred",
			},
		}

		statusListCredential, err := GenerateStatusList2021Credential(revocationID, testIssuer, StatusRevocation, []credential.VerifiableCredential{testCred1, testCred2})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, statusListCredential)

		subjectBytes, err := json.Marshal(statusListCredential.CredentialSubject)
		assert.NoError(tt, err)

		var statusListCred StatusList2021Credential
		err = json.Unmarshal(subjectBytes, &statusListCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, statusListCred)

		assert.Equal(tt, statusListCred.ID, revocationID)
		assert.Equal(tt, statusListCred.Type, StatusList2021Type)
		assert.True(tt, len(statusListCred.EncodedList) > 0)
		assert.Equal(tt, statusListCred.StatusPurpose, StatusRevocation)
	})

	t.Run("mismatched credential status purposes", func(tt *testing.T) {
		revocationID := "revocation-id"
		testIssuer := "test-issuer"
		testCred1 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-1",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "123",
				StatusListCredential: "test-cred",
			},
		}
		testCred2 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-2",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusSuspension,
				StatusListIndex:      "124",
				StatusListCredential: "test-cred",
			},
		}

		_, err := GenerateStatusList2021Credential(revocationID, testIssuer, StatusRevocation, []credential.VerifiableCredential{testCred1, testCred2})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential<test-verifiable-credential-2> has a different "+
			"status purpose<suspension> value than the status credential<revocation>")
	})

	t.Run("duplicate credential status index values", func(tt *testing.T) {
		revocationID := "revocation-id"
		testIssuer := "test-issuer"
		testCred1 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-1",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "123",
				StatusListCredential: "test-cred",
			},
		}
		testCred2 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-2",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "123",
				StatusListCredential: "test-cred",
			},
		}

		_, err := GenerateStatusList2021Credential(revocationID, testIssuer, StatusRevocation, []credential.VerifiableCredential{testCred1, testCred2})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "has a duplicate status list index value")
	})

	t.Run("no credentials", func(tt *testing.T) {
		revocationID := "revocation-id"
		testIssuer := "test-issuer"

		emptyStatusListCred, err := GenerateStatusList2021Credential(revocationID, testIssuer, StatusRevocation, []credential.VerifiableCredential{})
		assert.NotEmpty(tt, emptyStatusListCred)
		assert.NoError(tt, err)
	})

	t.Run("invalid index value", func(tt *testing.T) {
		revocationID := "revocation-id"
		testIssuer := "test-issuer"
		testCred1 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-1",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "-1",
				StatusListCredential: "test-cred",
			},
		}

		_, err := GenerateStatusList2021Credential(revocationID, testIssuer, StatusRevocation, []credential.VerifiableCredential{testCred1})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid status list index value, not a valid positive integer: -1")
	})

	t.Run("missing index value", func(tt *testing.T) {
		revocationID := "revocation-id"
		testIssuer := "test-issuer"
		testCred1 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-1",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "-1",
				StatusListCredential: "test-cred",
			},
		}

		_, err := GenerateStatusList2021Credential(revocationID, testIssuer, StatusRevocation, []credential.VerifiableCredential{testCred1})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "not a valid positive integer")
	})
}

func TestValidateCredentialInStatusList(t *testing.T) {
	t.Run("happy path validation", func(tt *testing.T) {
		revocationID := "revocation-id"
		testIssuer := "test-issuer"
		testCred1 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-1",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "123",
				StatusListCredential: "test-cred",
			},
		}

		statusListCredential, err := GenerateStatusList2021Credential(revocationID, testIssuer, StatusRevocation, []credential.VerifiableCredential{testCred1})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, statusListCredential)

		// valid = revoked
		valid, err := ValidateCredentialInStatusList(testCred1, *statusListCredential)
		assert.NoError(tt, err)
		assert.True(tt, valid)
	})

	t.Run("check for missing cred", func(tt *testing.T) {
		revocationID := "revocation-id"
		testIssuer := "test-issuer"
		testCred1 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-1",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "123",
				StatusListCredential: "test-cred",
			},
		}
		testCred2 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-2",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "124",
				StatusListCredential: "test-cred",
			},
		}

		statusListCredential, err := GenerateStatusList2021Credential(revocationID, testIssuer, StatusRevocation, []credential.VerifiableCredential{testCred1})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, statusListCredential)

		// valid = revoked
		valid, err := ValidateCredentialInStatusList(testCred2, *statusListCredential)
		assert.NoError(tt, err)
		assert.False(tt, valid)
	})

	t.Run("invalid bitstring value in status list credential", func(tt *testing.T) {
		revocationID := "revocation-id"
		testIssuer := "test-issuer"
		testCred1 := credential.VerifiableCredential{
			Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
				"https://w3id.org/security/suites/jws-2020/v1"},
			ID:           "test-verifiable-credential-2",
			Type:         []string{"VerifiableCredential"},
			Issuer:       testIssuer,
			IssuanceDate: "2021-01-01T19:23:24Z",
			CredentialSubject: map[string]interface{}{
				"id":      "test-vc-id-1",
				"company": "Block",
				"website": "https://block.xyz",
			},
			CredentialStatus: StatusList2021Entry{
				ID:                   revocationID,
				Type:                 StatusList2021EntryType,
				StatusPurpose:        StatusRevocation,
				StatusListIndex:      "123",
				StatusListCredential: "test-cred",
			},
		}

		// valid = revoked
		valid, err := ValidateCredentialInStatusList(testCred1, testCred1)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential<test-verifiable-credential-2> is not a valid status credential")
		assert.False(tt, valid)
	})
}

func TestBitstringGenerationAndExpansion(t *testing.T) {
	t.Run("happy path", func(tt *testing.T) {
		credIndices := []string{"123", "112", "440185", "52058", "9999"}
		compressedBitstring, err := bitstringGeneration(credIndices)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, compressedBitstring)

		expandedBitstring, err := bitstringExpansion(compressedBitstring)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, expandedBitstring)

		// sort and compare
		sort.Strings(credIndices)
		sort.Strings(expandedBitstring)
		assert.EqualValues(tt, credIndices, expandedBitstring)
	})

	t.Run("no elements", func(tt *testing.T) {
		var credIndices []string
		bitString, err := bitstringGeneration(credIndices)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, bitString)
	})

	t.Run("invalid elements", func(tt *testing.T) {
		credIndices := []string{"-1", "2", "3"}
		bitString, err := bitstringGeneration(credIndices)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid status list index value, not a valid positive integer: -1")
		assert.Empty(tt, bitString)
	})

	t.Run("repeated elements", func(tt *testing.T) {
		credIndices := []string{"2", "2", "3"}
		bitString, err := bitstringGeneration(credIndices)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "duplicate status list index value found: 2")
		assert.Empty(tt, bitString)
	})
}
