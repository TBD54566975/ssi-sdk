package main

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	sdjwt "github.com/TBD54566975/ssi-sdk/sd-jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Create a struct that implements sd_jwt.Signer. Here we use the lestrat-go/jwx library to sign arbitrary payloads.
type lestratSigner struct {
	signer jwx.Signer
}

func (s lestratSigner) Sign(blindedClaimsData []byte) ([]byte, error) {
	insecureSDJWT, err := jwt.ParseInsecure(blindedClaimsData)
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(insecureSDJWT, jwt.WithKey(jwa.KeyAlgorithmFrom(s.signer.ALG), s.signer.PrivateKey))
	if err != nil {
		return nil, err
	}
	return signed, nil
}

func main() {
	// This is an example of how this could be used in a real use case. Imagine that Alice is going to a bar. Before
	// entering, that bar will require her to proof that she is of legal drinking age. Alice can do this with a
	// digital credential that's been issued to her by the DMV. That digital credential contains, among other things,
	// her date of birth.
	// But Alice doesn't want to over share information with the bar! She is not willing to disclose anything about her
	// except for her age. How does she do that? Follow the example below.

	// The DMV is the issuer of the credential. Let's give them an ID in the form of a DID.
	issuerPrivKey, issuerDID, _ := key.GenerateDIDKey(crypto.P256)
	expandedIssuerDID, _ := issuerDID.Expand()
	issuerKID := expandedIssuerDID.VerificationMethod[0].ID

	credentialClaims := []byte(`{
  "first_name": "Alice",
  "address": "123 McAlice St, NY",
  "date_of_birth": "1967-01-24"
}`)
	// The issuer needs to issue a credential that *enables* Alice to choose what pieces she wished to disclose. The
	// bits below are the technical setup so the issuer can sign using the private key we created above.
	issuerSigner, _ := jwx.NewJWXSigner(issuerDID.String(), issuerKID, issuerPrivKey)
	signer := sdjwt.NewSDJWTSigner(&lestratSigner{
		*issuerSigner,
	}, sdjwt.NewSaltGenerator(16))

	// This is the important bit, the issuers tells the library: "please blind the following fields in a credential,
	// so the user can select when to disclose them".
	issuanceFormat, err := signer.BlindAndSign(credentialClaims, map[string]sdjwt.BlindOption{
		"first_name":    sdjwt.RecursiveBlindOption{},
		"address":       sdjwt.RecursiveBlindOption{},
		"date_of_birth": sdjwt.RecursiveBlindOption{},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Prints something like the following
	// eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJfc2QiOlsiNzZRT2p6M3FackdsaUpBSEN2RmR5M1E3dFNuVnU5bEZRU0syejJZQVg3dyIsIm5LZWlQSUdTSkd1cG1TM09rckM2M2pVbkVYMml5R1JxV1VnNklJeUc1TEEiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.tBVz1_ilURbGQxqpEqKTlJb25-i6VbdBdy_7dqmLAU1Z8Rl98UgYTQfaTgaGNRyv-lIWj5uk57mWz-qkwndurw~WyJqQjZIN2QxdnVGWFp1NTFLZ1ZWQjdRIiwgImZpcnN0TmFtZSIsICJBbGljZSJd
	fmt.Println("Combined Issuance Format")
	fmt.Println(string(issuanceFormat)) // Prints an SD-JWT with a single disclosure.

	// The payload of the JWT part is similar to the one below.
	// {
	//   "_sd": [
	//     "SOrZvk75qTMsrsf4qvcgefSm1HhftWh-UAudjN7tNN8",
	//     "minU6A21faKMQnVmfSABThLh6I08b0nIGQXHRBpgFCM",
	//     "QvcUASQPr29w3wwY_I9tVSAIVLWSef-xS2K1x5O2oRw",
	//     "u2-9RWthc5b2TOydn5Gigo83QL_XQlyvdKe7x0amqOA"
	//   ],
	//   "_sd_alg": "sha-256"
	// }
	//
	// The base64url decoded values for the disclosure are similar to the ones below
	// [
	//   "EfUhqQP5vjPwrsh4_r3z1g",
	//   "address",
	//   "123 McAlice St, NY"
	// ]
	//
	// [
	//   "3alx_CdsRq6a6EOkCDBkUw",
	//   "date_of_birth",
	//   "1967-01-24"
	// ]
	//
	// [
	//   "N_8M0vcc3y9n0Vxf-2t1_A",
	//   "first_name",
	//   "Alice"
	// ]

	// Great, so now Alice has a credential that was issued by the DMV. Now let's go ahead and present that to the bar.
	// But we'll take care to only include the date_of_birth info into what we're presenting!
	idxOfDisclosuresToPresent, _ := sdjwt.SelectDisclosures(issuanceFormat, map[string]struct{}{"date_of_birth": {}})
	sdPresentation := sdjwt.CreatePresentation(issuanceFormat, idxOfDisclosuresToPresent, nil)

	// Note that this will *only* contain a single disclosure (the one with the "date_of_birth").
	fmt.Println("Combined Format for Presentation")
	fmt.Println(string(sdPresentation))

	// Amazing! We've been able to only share pieces of information with the bar... but how does the bar know that
	// this information is legitimate? Easy, let's do some verification!

	// First the bar gets the *public* key from the issuer, which is part of the DID document they created.
	issuerKey, _ := expandedIssuerDID.VerificationMethod[0].PublicKeyJWK.ToPublicKey()
	// Then we verify it. This is too easy!
	processedPayload, err := sdjwt.VerifySDPresentation(sdPresentation,
		sdjwt.VerificationOptions{
			// We don't care about holder binding here.
			HolderBindingOption: sdjwt.SkipVerifyHolderBinding,
			Alg:                 expandedIssuerDID.VerificationMethod[0].PublicKeyJWK.ALG,
			IssuerKey:           issuerKey,
		})

	// A lack of error means that verification worked! Note that this says nothing related to the truthfulness of the
	// claim. The bar trusts the issuer (the DMV) for this.
	if err != nil {
		fmt.Println("This should never happen")
		return
	}

	// This will print all the fields that the verifier actually received.
	// map[date_of_birth:1967-01-24]
	fmt.Println("Verifier Processed Payload")
	fmt.Println(processedPayload)

	// Most excellent, well done!
}
