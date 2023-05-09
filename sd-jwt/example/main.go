package main

import (
	"fmt"

	sdjwt "ssi-sdk/sd-jwt"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
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
	issuerPrivKey, issuerDID, _ := key.GenerateDIDKey(crypto.P256)
	expandedIssuerDID, _ := issuerDID.Expand()
	issuerKID := expandedIssuerDID.VerificationMethod[0].ID

	issuerSigner, _ := jwx.NewJWXSigner(issuerDID.String(), issuerKID, issuerPrivKey)
	signer := sdjwt.NewSDJWTSigner(&lestratSigner{
		*issuerSigner,
	}, sdjwt.NewSaltGenerator(16))
	issuanceFormat, _ := signer.BlindAndSign([]byte(`{"firstName":"Alice"}`), map[string]sdjwt.BlindOption{
		"firstName": sdjwt.RecursiveBlindOption{},
	})

	// Prints something like the following
	// eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJfc2QiOlsiNzZRT2p6M3FackdsaUpBSEN2RmR5M1E3dFNuVnU5bEZRU0syejJZQVg3dyIsIm5LZWlQSUdTSkd1cG1TM09rckM2M2pVbkVYMml5R1JxV1VnNklJeUc1TEEiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.tBVz1_ilURbGQxqpEqKTlJb25-i6VbdBdy_7dqmLAU1Z8Rl98UgYTQfaTgaGNRyv-lIWj5uk57mWz-qkwndurw~WyJqQjZIN2QxdnVGWFp1NTFLZ1ZWQjdRIiwgImZpcnN0TmFtZSIsICJBbGljZSJd
	//
	// The payload of the JWT piece is similar to the one below.
	// {
	//   "_sd": [
	//     "76QOjz3qZrGliJAHCvFdy3Q7tSnVu9lFQSK2z2YAX7w",
	//     "nKeiPIGSJGupmS3OkrC63jUnEX2iyGRqWUg6IIyG5LA"
	//   ],
	//   "_sd_alg": "sha-256"
	// }
	//
	// The base64url decoded value of the disclosure is similar to the one below
	// [
	//   "jB6H7d1vuFXZu51KgVVB7Q",
	//   "firstName",
	//   "Alice"
	// ]
	fmt.Println(string(issuanceFormat)) // Prints an SD-JWT with a single disclosure.
}
