package manifest

import (
	"embed"
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

const (
	ManifestVector1    string = "cm-manifest-example-1.json"
	ManifestVector2    string = "cm-manifest-example-2.json"
	ApplicationVector1 string = "cm-application-example-1.json"
	CredentialVector1  string = "cm-credential-example-1.json"
	ResponseVector1    string = "cm-response-example-1.json"
	ResponseVector2    string = "cm-response-example-2.json"

	FullApplicationVector string = "full-application.json"
	FullCredentialVector  string = "full-credential.json"
	FullManifestVector    string = "full-manifest.json"
)

var (
	//go:embed testdata
	testVectors embed.FS
)

// Round trip de/serialize to test our object models, and check validity

func TestCredentialManifest(t *testing.T) {
	// examples here https://identity.foundation/credential-manifest/#credential-response

	t.Run("Credential Manifest Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(ManifestVector1)
		assert.NoError(tt, err)

		var man CredentialManifest
		err = json.Unmarshal([]byte(vector), &man)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, man)

		assert.NoError(tt, man.IsValid())

		roundTripBytes, err := json.Marshal(man)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Credential Manifest Vector 2", func(tt *testing.T) {
		vector, err := getTestVector(ManifestVector2)
		assert.NoError(tt, err)

		type outputDescriptors struct {
			OutputDescriptors []OutputDescriptor `json:"output_descriptors" validate:"required"`
		}

		var od outputDescriptors
		err = json.Unmarshal([]byte(vector), &od)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, od)

		for _, d := range od.OutputDescriptors {
			assert.NoError(tt, d.IsValid())
		}

		roundTripBytes, err := json.Marshal(od)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func TestCredentialApplication(t *testing.T) {
	// example here https://identity.foundation/credential-manifest/#credential-application---simple-example

	t.Run("Credential Application Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(ApplicationVector1)
		assert.NoError(tt, err)

		var app CredentialApplication
		err = json.Unmarshal([]byte(vector), &app)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, app)

		assert.NoError(tt, app.IsValid())

		roundTripBytes, err := json.Marshal(app)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func TestCredentialResponse(t *testing.T) {
	// example here https://identity.foundation/credential-manifest/#credential-response

	t.Run("Credential Response - Fulfillment Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(ResponseVector1)
		assert.NoError(tt, err)

		var response CredentialResponse
		err = json.Unmarshal([]byte(vector), &response)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, response)

		assert.NoError(tt, response.IsValid())

		roundTripBytes, err := json.Marshal(response)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Credential Response - Denial Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(ResponseVector2)
		assert.NoError(tt, err)

		var response CredentialResponse
		err = json.Unmarshal([]byte(vector), &response)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, response)

		assert.NoError(tt, response.IsValid())

		roundTripBytes, err := json.Marshal(response)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func getValidTestCmCaVc(tt *testing.T) (CredentialManifest, CredentialApplication, []credential.VerifiableCredential) {

	// manifest
	manifestJSON, err := getTestVector(FullManifestVector)
	assert.NoError(tt, err)

	var cm CredentialManifest
	err = json.Unmarshal([]byte(manifestJSON), &cm)

	assert.NoError(tt, err)
	assert.NotEmpty(tt, cm)
	assert.NoError(tt, cm.IsValid())

	// application
	credAppJSON, err := getTestVector(FullApplicationVector)
	assert.NoError(tt, err)

	var ca CredentialApplication
	err = json.Unmarshal([]byte(credAppJSON), &ca)

	assert.NoError(tt, err)
	assert.NotEmpty(tt, ca)
	assert.NoError(tt, ca.IsValid())

	vcJSON, err := getTestVector(FullCredentialVector)
	assert.NoError(tt, err)

	var vc credential.VerifiableCredential
	err = json.Unmarshal([]byte(vcJSON), &vc)

	assert.NoError(tt, err)
	assert.NotEmpty(tt, vc)
	assert.NoError(tt, vc.IsValid())

	return cm, ca, []credential.VerifiableCredential{vc}
}

func TestIsValidCredentialApplicationForManifest(t *testing.T) {

	t.Run("Credential Application and Credential Manifest Pair Valid", func(tt *testing.T) {
		cm, ca, vcs := getValidTestCmCaVc(tt)

		err := IsValidCredentialApplicationForManifest(cm, ca, vcs...)

		assert.NoError(tt, err)
	})

	t.Run("Credential Application and Credential Manifest Pair Full Test", func(tt *testing.T) {

		cm, ca, vcs := getValidTestCmCaVc(tt)

		ca.ManifestID = "bad-id"

		err := IsValidCredentialApplicationForManifest(cm, ca, vcs...)
		assert.Contains(t, err.Error(), "the credential application's manifest id: WA-DL-CLASS-A must be equal to the credential manifest's id: bad-id")

		// reset
		ca.ManifestID = cm.ID

		// test claim format
		cm.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		ca.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		err = IsValidCredentialApplicationForManifest(cm, ca, vcs...)
		assert.NoError(tt, err)

		cm.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			LDP: &exchange.LDPType{ProofType: []cryptosuite.SignatureType{"sigtype"}},
		}

		ca.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		err = IsValidCredentialApplicationForManifest(cm, ca, vcs...)
		assert.NoError(tt, err)

		cm.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		ca.Format = &exchange.ClaimFormat{
			LDP: &exchange.LDPType{ProofType: []cryptosuite.SignatureType{"sigtype"}},
		}

		err = IsValidCredentialApplicationForManifest(cm, ca, vcs...)
		assert.Contains(t, err.Error(), "credential application's format must be a subset of the format property in the credential manifest")

		// reset
		ca.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		ca.PresentationSubmission.DefinitionID = "badid"

		err = IsValidCredentialApplicationForManifest(cm, ca, vcs...)
		assert.Contains(t, err.Error(), "credential application's presentation submission's definition id: 32f54163-7166-48f1-93d8-ff217bdb0653 does not match the credential manifest's id: badid")

		// reset
		cm, ca, vcs = getValidTestCmCaVc(tt)

		err = IsValidCredentialApplicationForManifest(cm, ca, vcs...)
		assert.NoError(tt, err)

		ca.PresentationSubmission.DescriptorMap[0].Format = "badformat"

		err = IsValidCredentialApplicationForManifest(cm, ca, vcs...)
		assert.Contains(t, err.Error(), "format must be one of the following:")

		// reset
		ca.PresentationSubmission.DescriptorMap[0].Format = "jwt_vc"

		err = IsValidCredentialApplicationForManifest(cm, ca, vcs...)
		assert.NoError(tt, err)

		ca.PresentationSubmission.DescriptorMap[0].Path = "bad-path"

		err = IsValidCredentialApplicationForManifest(cm, ca, vcs...)
		assert.Contains(t, err.Error(), "invalid json path: bad-path")

	})

	t.Run("PresentationSubmission DescriptorMap mismatch id", func(tt *testing.T) {
		cm, ca, vcs := getValidTestCmCaVc(tt)

		ca.PresentationSubmission.DescriptorMap[0].ID = "badbadid"
		err := IsValidCredentialApplicationForManifest(cm, ca, vcs...)

		assert.Contains(t, err.Error(), "unfulfilled input descriptor")
	})

	t.Run("VC path fulfilled", func(tt *testing.T) {
		cm, ca, vcs := getValidTestCmCaVc(tt)

		cm.PresentationDefinition.InputDescriptors[0].Constraints.Fields[0].Path[0] = "$.credentialSubject.badPath"
		cm.PresentationDefinition.InputDescriptors[0].Constraints.Fields[0].ID = "badPath"
		err := IsValidCredentialApplicationForManifest(cm, ca, vcs[0])

		assert.Contains(t, err.Error(), "not fulfilled for field")
	})

	t.Run("InputDescriptors format mismatch", func(tt *testing.T) {
		cm, ca, vcs := getValidTestCmCaVc(tt)

		cm.PresentationDefinition.InputDescriptors[0].Format = &exchange.ClaimFormat{
			LDP: &exchange.LDPType{ProofType: []cryptosuite.SignatureType{cryptosuite.JSONWebSignature2020}},
		}

		err := IsValidCredentialApplicationForManifest(cm, ca, vcs[0])

		assert.Contains(t, err.Error(), "is not one of the supported formats:")
	})

	t.Run("Not all input descriptors fulfilled", func(tt *testing.T) {
		cm, ca, vcs := getValidTestCmCaVc(tt)

		ca.PresentationSubmission.DescriptorMap = ca.PresentationSubmission.DescriptorMap[:len(ca.PresentationSubmission.DescriptorMap)-1]
		err := IsValidCredentialApplicationForManifest(cm, ca, vcs[0])

		assert.Contains(t, err.Error(), "unfulfilled input descriptor")
	})

	t.Run("one cred can fulfill multiple input descriptors", func(tt *testing.T) {
		cm, ca, vcs := getValidTestCmCaVc(tt)

		cm.PresentationDefinition.InputDescriptors = append(cm.PresentationDefinition.InputDescriptors, cm.PresentationDefinition.InputDescriptors[0])
		cm.PresentationDefinition.InputDescriptors[1].ID = "kycid2"
		ca.PresentationSubmission.DescriptorMap = append(ca.PresentationSubmission.DescriptorMap, ca.PresentationSubmission.DescriptorMap[0])
		ca.PresentationSubmission.DescriptorMap[1].ID = "kycid2"

		err := IsValidCredentialApplicationForManifest(cm, ca, vcs[0])

		assert.NoError(tt, err)
	})

	t.Run("multiple creds can fulfill multiple input descriptors", func(tt *testing.T) {
		cm, ca, vcs := getValidTestCmCaVc(tt)

		vcs = append(vcs, vcs[0])

		cm.PresentationDefinition.InputDescriptors = append(cm.PresentationDefinition.InputDescriptors, cm.PresentationDefinition.InputDescriptors[0])
		cm.PresentationDefinition.InputDescriptors[1].ID = "kycid2"

		ca.PresentationSubmission.DescriptorMap = append(ca.PresentationSubmission.DescriptorMap, ca.PresentationSubmission.DescriptorMap[0])
		ca.PresentationSubmission.DescriptorMap[1].ID = "kycid2"
		ca.PresentationSubmission.DescriptorMap[1].Path = "$[1]"

		err := IsValidCredentialApplicationForManifest(cm, ca, vcs...)

		assert.NoError(tt, err)
	})

	t.Run("vc path does not exist", func(tt *testing.T) {
		cm, ca, vcs := getValidTestCmCaVc(tt)

		vcs = append(vcs, vcs[0])

		cm.PresentationDefinition.InputDescriptors = append(cm.PresentationDefinition.InputDescriptors, cm.PresentationDefinition.InputDescriptors[0])
		cm.PresentationDefinition.InputDescriptors[1].ID = "kycid2"

		ca.PresentationSubmission.DescriptorMap = append(ca.PresentationSubmission.DescriptorMap, ca.PresentationSubmission.DescriptorMap[0])
		ca.PresentationSubmission.DescriptorMap[1].ID = "kycid2"
		ca.PresentationSubmission.DescriptorMap[1].Path = "$[3]"

		err := IsValidCredentialApplicationForManifest(cm, ca, vcs...)

		assert.Contains(t, err.Error(), "could not resolve claim from submission descriptor<kycid2> with path: $[3]")
	})

	t.Run("only ca cm validation, no vcs", func(tt *testing.T) {
		cm, ca, _ := getValidTestCmCaVc(tt)

		cm.PresentationDefinition = nil
		err := IsValidCredentialApplicationForManifest(cm, ca)

		assert.NoError(tt, err)
	})

}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
