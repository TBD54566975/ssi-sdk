package manifest

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsValidCredentialApplicationForManifest(t *testing.T) {
	t.Run("Credential Application and Credential Manifest Pair Valid", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)

		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.NoError(tt, err)
		assert.Empty(tt, unfulfilledIDs)
	})

	t.Run("Credential Application and Credential Manifest Pair Valid with JWT", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplicationJWTCred(tt)

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)

		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.NoError(tt, err)
		assert.Empty(tt, unfulfilledIDs)
	})

	t.Run("Credential Application and Credential Manifest Pair Full Test", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)

		ca.CredentialApplication.ManifestID = "bad-id"

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)

		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "the credential application's manifest id: bad-id must be equal to the credential manifest's id: WA-DL-CLASS-A")
		assert.Empty(tt, unfulfilledIDs)

		// reset
		ca.CredentialApplication.ManifestID = cm.ID

		// test claim format
		cm.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		ca.CredentialApplication.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		credAppRequestBytes, err = json.Marshal(ca)
		assert.NoError(tt, err)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err = IsValidCredentialApplicationForManifest(cm, request)
		assert.NoError(tt, err)
		assert.Empty(tt, unfulfilledIDs)

		cm.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			LDP: &exchange.LDPType{ProofType: []cryptosuite.SignatureType{"sigtype"}},
		}

		ca.CredentialApplication.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		credAppRequestBytes, err = json.Marshal(ca)
		assert.NoError(tt, err)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err = IsValidCredentialApplicationForManifest(cm, request)
		assert.NoError(tt, err)
		assert.Empty(tt, unfulfilledIDs)

		cm.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		ca.CredentialApplication.Format = &exchange.ClaimFormat{
			LDP: &exchange.LDPType{ProofType: []cryptosuite.SignatureType{"sigtype"}},
		}

		credAppRequestBytes, err = json.Marshal(ca)
		assert.NoError(tt, err)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err = IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "credential application's format must be a subset of the format property in the credential manifest")
		assert.Empty(tt, unfulfilledIDs)

		// reset
		ca.CredentialApplication.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		ca.CredentialApplication.PresentationSubmission.DefinitionID = "badid"

		credAppRequestBytes, err = json.Marshal(ca)
		assert.NoError(tt, err)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err = IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "credential application's presentation submission's definition id: badid does not match the credential manifest's id: 32f54163-7166-48f1-93d8-ff217bdb0653")
		assert.Empty(tt, unfulfilledIDs)

		// reset
		cm, ca = getValidTestCredManifestCredApplication(tt)
		credAppRequestBytes, err = json.Marshal(ca)
		assert.NoError(tt, err)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err = IsValidCredentialApplicationForManifest(cm, request)
		assert.NoError(tt, err)
		assert.Empty(tt, unfulfilledIDs)

		ca.CredentialApplication.PresentationSubmission.DescriptorMap[0].Format = "badformat"

		credAppRequestBytes, err = json.Marshal(ca)
		assert.NoError(tt, err)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err = IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "value must be one of")
		assert.Empty(tt, unfulfilledIDs)

		// reset
		ca.CredentialApplication.PresentationSubmission.DescriptorMap[0].Format = "jwt_vc"

		credAppRequestBytes, err = json.Marshal(ca)
		assert.NoError(tt, err)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err = IsValidCredentialApplicationForManifest(cm, request)
		assert.NoError(tt, err)
		assert.Empty(tt, unfulfilledIDs)

		ca.CredentialApplication.PresentationSubmission.DescriptorMap[0].Path = "bad-path"

		credAppRequestBytes, err = json.Marshal(ca)
		assert.NoError(tt, err)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err = IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "invalid json path: bad-path")
		assert.Empty(tt, unfulfilledIDs)
	})

	t.Run("PresentationSubmission DescriptorMap mismatch id", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)
		ca.CredentialApplication.PresentationSubmission.DescriptorMap[0].ID = "badbadid"

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)
		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "unfulfilled input descriptor")
		assert.Len(tt, unfulfilledIDs, 1)
	})

	t.Run("VC path fulfilled", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)

		cm.PresentationDefinition.InputDescriptors[0].Constraints.Fields[0].Path[0] = "$.credentialSubject.badPath"
		cm.PresentationDefinition.InputDescriptors[0].Constraints.Fields[0].ID = "badPath"

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)
		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "<1>unfulfilled input descriptor(s)")
		assert.Len(tt, unfulfilledIDs, 1)
		assert.Contains(tt, unfulfilledIDs[cm.PresentationDefinition.InputDescriptors[0].ID], "not fulfilled for field")
	})

	t.Run("InputDescriptors format mismatch", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)

		cm.PresentationDefinition.InputDescriptors[0].Format = &exchange.ClaimFormat{
			LDP: &exchange.LDPType{ProofType: []cryptosuite.SignatureType{cryptosuite.JSONWebSignature2020}},
		}

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)
		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "<1>unfulfilled input descriptor(s)")
		assert.Len(tt, unfulfilledIDs, 1)
		assert.Contains(tt, unfulfilledIDs[cm.PresentationDefinition.InputDescriptors[0].ID], "is not one of the supported formats")
	})

	t.Run("Not all input descriptors fulfilled", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)
		ca.CredentialApplication.PresentationSubmission.DescriptorMap = ca.CredentialApplication.PresentationSubmission.DescriptorMap[:len(ca.CredentialApplication.PresentationSubmission.DescriptorMap)-1]

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)
		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "no descriptors provided for application")
		assert.Empty(tt, unfulfilledIDs)
	})

	t.Run("one cred can fulfill multiple input descriptors", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)

		cm.PresentationDefinition.InputDescriptors = append(cm.PresentationDefinition.InputDescriptors, cm.PresentationDefinition.InputDescriptors[0])
		cm.PresentationDefinition.InputDescriptors[1].ID = "kycid2"
		ca.CredentialApplication.PresentationSubmission.DescriptorMap = append(ca.CredentialApplication.PresentationSubmission.DescriptorMap, ca.CredentialApplication.PresentationSubmission.DescriptorMap[0])
		ca.CredentialApplication.PresentationSubmission.DescriptorMap[1].ID = "kycid2"

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)
		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.NoError(tt, err)
		assert.Empty(tt, unfulfilledIDs)
	})

	t.Run("multiple creds can fulfill multiple input descriptors", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)
		// add second cred
		ca.Credentials = append(ca.Credentials, ca.Credentials[0])

		cm.PresentationDefinition.InputDescriptors = append(cm.PresentationDefinition.InputDescriptors, cm.PresentationDefinition.InputDescriptors[0])
		cm.PresentationDefinition.InputDescriptors[1].ID = "kycid2"

		ca.CredentialApplication.PresentationSubmission.DescriptorMap = append(ca.CredentialApplication.PresentationSubmission.DescriptorMap, ca.CredentialApplication.PresentationSubmission.DescriptorMap[0])
		ca.CredentialApplication.PresentationSubmission.DescriptorMap[1].ID = "kycid2"
		ca.CredentialApplication.PresentationSubmission.DescriptorMap[1].Path = "$.verifiableCredentials[1]"

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)
		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.NoError(tt, err)
		assert.Empty(tt, unfulfilledIDs)
	})

	t.Run("vc path does not exist", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)
		cm.PresentationDefinition.InputDescriptors = append(cm.PresentationDefinition.InputDescriptors, cm.PresentationDefinition.InputDescriptors[0])
		cm.PresentationDefinition.InputDescriptors[1].ID = "kycid2"

		ca.CredentialApplication.PresentationSubmission.DescriptorMap = append(ca.CredentialApplication.PresentationSubmission.DescriptorMap, ca.CredentialApplication.PresentationSubmission.DescriptorMap[0])
		ca.CredentialApplication.PresentationSubmission.DescriptorMap[1].ID = "kycid2"
		ca.CredentialApplication.PresentationSubmission.DescriptorMap[1].Path = "$.verifiableCredentials[3]"

		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)
		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.Contains(t, err.Error(), "<1>unfulfilled input descriptor(s)")
		assert.Len(tt, unfulfilledIDs, 1)
		assert.Contains(tt, unfulfilledIDs[cm.PresentationDefinition.InputDescriptors[1].ID], "could not resolve claim from submission descriptor<kycid2> with path: $.verifiableCredentials[3]")
	})

	t.Run("invalid credential application, presentation submission with no presentation definition in the manifest", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)
		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)
		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		cm.PresentationDefinition = nil
		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.Error(tt, err)
		assert.Empty(tt, unfulfilledIDs)
		assert.Contains(tt, err.Error(), "the credential manifest's presentation definition is empty")
	})

	t.Run("only ca cm validation, no vcs", func(tt *testing.T) {
		cm, ca := getValidTestCredManifestCredApplication(tt)
		ca.CredentialApplication.PresentationSubmission = nil
		credAppRequestBytes, err := json.Marshal(ca)
		assert.NoError(tt, err)
		request := make(map[string]any)
		err = json.Unmarshal(credAppRequestBytes, &request)
		assert.NoError(tt, err)

		cm.PresentationDefinition = nil
		unfulfilledIDs, err := IsValidCredentialApplicationForManifest(cm, request)
		assert.NoError(tt, err)
		assert.Empty(tt, unfulfilledIDs)
	})
}

func getValidTestCredManifestCredApplication(t *testing.T) (CredentialManifest, CredentialApplicationWrapper) {
	// manifest
	manifestJSON, err := getTestVector(FullManifestVector)
	require.NoError(t, err)

	var cm CredentialManifest
	err = json.Unmarshal([]byte(manifestJSON), &cm)

	require.NoError(t, err)
	require.NotEmpty(t, cm)
	require.NoError(t, cm.IsValid())

	// application
	credAppJSON, err := getTestVector(FullApplicationVector)
	require.NoError(t, err)

	var ca CredentialApplication
	err = json.Unmarshal([]byte(credAppJSON), &ca)

	require.NoError(t, err)
	require.NotEmpty(t, ca)
	require.NoError(t, ca.IsValid())

	vcJSON, err := getTestVector(FullCredentialVector)
	require.NoError(t, err)

	var vc credential.VerifiableCredential
	err = json.Unmarshal([]byte(vcJSON), &vc)

	require.NoError(t, err)
	require.NotEmpty(t, vc)
	require.NoError(t, vc.IsValid())

	return cm, CredentialApplicationWrapper{CredentialApplication: ca, Credentials: []any{vc}}
}

func getValidTestCredManifestCredApplicationJWTCred(t *testing.T) (CredentialManifest, CredentialApplicationWrapper) {
	// manifest
	manifestJSON, err := getTestVector(FullManifestVector)
	require.NoError(t, err)

	var cm CredentialManifest
	err = json.Unmarshal([]byte(manifestJSON), &cm)

	require.NoError(t, err)
	require.NotEmpty(t, cm)
	require.NoError(t, cm.IsValid())

	// application
	credAppJSON, err := getTestVector(FullApplicationVector)
	require.NoError(t, err)

	var ca CredentialApplication
	err = json.Unmarshal([]byte(credAppJSON), &ca)

	require.NoError(t, err)
	require.NotEmpty(t, ca)
	require.NoError(t, ca.IsValid())

	vcJSON, err := getTestVector(FullCredentialVector)
	require.NoError(t, err)

	var vc credential.VerifiableCredential
	err = json.Unmarshal([]byte(vcJSON), &vc)
	require.NoError(t, err)
	require.NotEmpty(t, vc)
	require.NoError(t, vc.IsValid())

	// turn into a jwt
	_, privKey, err := crypto.GenerateEd25519Key()
	require.NoError(t, err)
	signer, err := jwx.NewJWXSigner("test-id", "test-kid", privKey)
	require.NoError(t, err)
	jwt, err := credential.SignVerifiableCredentialJWT(*signer, vc)
	require.NoError(t, err)
	require.NotEmpty(t, jwt)

	return cm, CredentialApplicationWrapper{CredentialApplication: ca, Credentials: []any{string(jwt)}}
}
