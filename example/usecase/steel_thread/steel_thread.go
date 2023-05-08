// Annotated steel thread flow for calling out all signing, verification, and key management.
// This example is focused on the signing, exchange, and verification of objects.

// We assume there are two parties:
//	1 . Alice, using a wallet, applying for a credential
//	2. An issuer via the SSI Service, processing credential applications and issuing credentials

// Each party has a single DID. Alice and the SSI Service each have a single did:key DID.
// Alice stores her DID’s private key in her wallet.
// The SSI Service stores its private key in the service key store database.

package main

import (
	"embed"
	"fmt"

	"github.com/goccy/go-json"

	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/example"
)

type Entity struct {
	didKey                key.DIDKey
	verifier              jwx.Verifier
	credentialManifest    manifest.CredentialManifest
	credentialApplication manifest.CredentialApplication
	credentialResponse    manifest.CredentialResponse
	verifiableCredentials []credential.VerifiableCredential
}

var (
	//go:embed testdata
	exampleFS embed.FS
)

func (t *Entity) GenerateWallet() {
	walletDIDPrivateKey, walletDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
	example.HandleExampleError(err, "Failed to generate DID")
	walletSigner, err := jwx.NewJWXSigner(walletDIDKey.String(), walletDIDKey.String(), walletDIDPrivateKey)
	example.HandleExampleError(err, "Failed to generate signer")
	walletVerifier, err := walletSigner.ToVerifier(walletSigner.ID)
	example.HandleExampleError(err, "Failed to generate verifier")

	t.didKey = *walletDIDKey
	t.verifier = *walletVerifier
}

func (t *Entity) CreateCredentialManifest() {
	credManifest := createCredentialManifest(t.didKey.String())
	t.credentialManifest = credManifest
}

func (t *Entity) CreateCredentialApplication() {
	credApplication := createCredentialApplication(t.credentialManifest)
	t.credentialApplication = credApplication
}

func (*Entity) SignCredentialManifest() {
	// TODO: SignCredentialManifestJWT(issuer) -> JWTString
}

func (*Entity) SignCredentialApplication() {
	// TODO: SignCredentialApplicationJWT(issuer) -> JWTString
}

func (*Entity) SignCredentialResponse() {
	// TODO: SignCredentialResponseJWT(issuer) -> JWTString
}

func (t *Entity) SetCredentialManifest(credManifest manifest.CredentialManifest) {
	t.credentialManifest = credManifest
}

func (t *Entity) SetCredentialApplication(application manifest.CredentialApplication) {
	t.credentialApplication = application
}

func (t *Entity) SetCredentialResponse(response manifest.CredentialResponse) {
	t.credentialResponse = response
}

func (t *Entity) SetVerifiableCredentials(credentials []credential.VerifiableCredential) {
	t.verifiableCredentials = credentials
}

func (t *Entity) ValidateCredentialManifest() error {
	// TODO: Validate Signature
	return t.credentialManifest.IsValid()
}

func (t *Entity) ValidateCredentialApplication() error {
	// TODO: Validate Signature
	return t.credentialApplication.IsValid()
}

func (t *Entity) ValidateCredentialResponse() error {
	// TODO: Validate Signature
	return t.credentialResponse.IsValid()
}

func (t *Entity) ValidateVerifiableCredentials() error {
	for _, vc := range t.verifiableCredentials {
		if vc.IsValid() != nil {
			return vc.IsValid()
		}
	}
	return nil
}

func (t *Entity) ProcessCredentialApplication(issuer string, subject string) (*manifest.CredentialResponse, []credential.VerifiableCredential) {
	var creds []credential.VerifiableCredential
	for i := 0; i < len(t.credentialManifest.OutputDescriptors); i++ {
		// TODO: Create Cred off of OD
		creds = append(creds, createVerifiableCredential(issuer, subject))
	}

	responseBuilder := manifest.NewCredentialResponseBuilder(t.credentialManifest.ID)

	if err := responseBuilder.SetApplicationID(t.credentialApplication.ID); err != nil {
		example.HandleExampleError(err, "could not fulfill credential application: could not set application id")
	}

	/**
		 The SSI Service creates a Credential Response, CR, signed with didI
	**/

	var descriptors []exchange.SubmissionDescriptor
	for i, c := range creds {
		format := string(exchange.JWTVC)

		descriptors = append(descriptors, exchange.SubmissionDescriptor{
			ID:     c.ID,
			Format: format,
			Path:   fmt.Sprintf("$.verifiableCredential[%d]", i),
		})
	}

	// set the information for the fulfilled credentials in the response
	if err := responseBuilder.SetFulfillment(descriptors); err != nil {
		example.HandleExampleError(err, "could not fulfill credential application: could not set fulfillment")
	}
	credRes, err := responseBuilder.Build()
	if err != nil {
		example.HandleExampleError(err, "could not build response")
	}

	return credRes, creds
}

func (t *Entity) FlexFullyValidatedCredentials() {
	_, _ = fmt.Print("\n#ShowingOffMyNewlyMintedCredentials: \n")
	for _, vc := range t.verifiableCredentials {
		_, _ = fmt.Print(vc.CredentialSubject)
	}
}

func main() {
	/**
		Step 1: Alice creates a DID, stored in her wallet, didW
	**/
	aliceWalletEntity := new(Entity)
	aliceWalletEntity.GenerateWallet()

	/**
		Step 2: The issuer creates a DID, stored in the SSI Service, didI
	**/
	issuerWalletEntity := new(Entity)
	issuerWalletEntity.GenerateWallet()

	/**
		Step 3: The Credential Manifest CM is created and signed by the Issuer, with didI
	**/
	issuerWalletEntity.CreateCredentialManifest()
	issuerWalletEntity.SignCredentialManifest()

	/**
		Step 4: Alice fetches `Credential Manifest` and…
			* Validates the signature using `didI`
			* Verifies it is a valid and well-formed Credential Manifest
	**/
	aliceWalletEntity.SetCredentialManifest(issuerWalletEntity.credentialManifest)
	if err := aliceWalletEntity.ValidateCredentialManifest(); err != nil {
		example.HandleExampleError(err, "could not verify credential manifest")
	}

	/**
		Step 5: Alice forms a response to Credential Manifest, Creates a Credential Application
	**/
	aliceWalletEntity.CreateCredentialApplication()
	aliceWalletEntity.SignCredentialApplication()

	/**
		Step 6: Alice submits `Credential Application` to the SSI Service. The SSI Service processes `Credential Application`...
			* Validates the signature using `didW`
			* Verifies it is a valid and well-formed Credential Application
			* Validates it complies with `CM`
	**/
	issuerWalletEntity.SetCredentialApplication(aliceWalletEntity.credentialApplication)
	if err := issuerWalletEntity.ValidateCredentialApplication(); err != nil {
		example.HandleExampleError(err, "could not verify credential application")
	}

	/**
		Step 7: The SSI Service creates Verifiable Credentials signed with `didI`. The SSI Service creates a
		Credential Response signed with `didI`
	**/
	credentialResponse, verifiableCredentials := issuerWalletEntity.ProcessCredentialApplication(issuerWalletEntity.didKey.String(), aliceWalletEntity.didKey.String())

	/**
		Step 8: Alice receives Credential Response containing the Verifiable Credentials and
			* Validates the signature of the `CR` using `didI`
			* Verifies `CR` and `VC` are well-formed
			* Verifies the signature(s) of `VC` using `didI`
			* Possible other validity checks, such as making sure the Credential is for Alice and has expected data

	**/
	aliceWalletEntity.SetCredentialResponse(*credentialResponse)
	if err := aliceWalletEntity.ValidateCredentialResponse(); err != nil {
		example.HandleExampleError(err, "could not verify credential response")
	}

	aliceWalletEntity.SetVerifiableCredentials(verifiableCredentials)
	if err := aliceWalletEntity.ValidateCredentialResponse(); err != nil {
		example.HandleExampleError(err, "could not verify verifiable credentials")
	}

	/**
		Step 8: Alice flexes her newly minted credentials to her friends and family
	**/
	aliceWalletEntity.FlexFullyValidatedCredentials()
}

func getFileBytes(filename string) []byte {
	caBytes, err := exampleFS.ReadFile(filename)

	if err != nil {
		example.HandleExampleError(err, "can not open file")
	}

	return caBytes
}

func createCredentialApplication(cm manifest.CredentialManifest) manifest.CredentialApplication {
	caBytes := getFileBytes("testdata/ca.json")

	var credApp manifest.CredentialApplication
	if err := json.Unmarshal(caBytes, &credApp); err != nil {
		example.HandleExampleError(err, "problem unmarshalling credential application")
	}

	credApp.ManifestID = cm.ID

	return credApp
}

func createVerifiableCredential(issuerDID string, walletDID string) credential.VerifiableCredential {
	vcBytes := getFileBytes("testdata/vc.json")

	var vc credential.VerifiableCredential
	if err := json.Unmarshal(vcBytes, &vc); err != nil {
		example.HandleExampleError(err, "problem unmarshalling verifiable credential")
	}

	credSubject := vc.CredentialSubject
	credSubject["id"] = walletDID

	builder := credential.NewVerifiableCredentialBuilder()
	_ = builder.SetIssuer(issuerDID)
	_ = builder.SetCredentialSubject(credSubject)
	_ = builder.SetCredentialSchema(*vc.CredentialSchema)
	_ = builder.SetIssuanceDate(vc.IssuanceDate)
	_ = builder.SetCredentialStatus(vc.CredentialStatus)
	_ = builder.SetEvidence(vc.Evidence)
	_ = builder.SetExpirationDate(vc.ExpirationDate)

	builderVC, err := builder.Build()
	if err != nil {
		example.HandleExampleError(err, "could not build verifiable credential")
	}

	return *builderVC
}

func createCredentialManifest(issuer string) manifest.CredentialManifest {
	manifestBytes := getFileBytes("testdata/cm.json")

	var m manifest.CredentialManifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		example.HandleExampleError(err, "problem unmarshalling credential m")
	}

	m.Issuer.ID = issuer
	return m
}
