// A simple application using a did:key.
// To learn more about DID's, please check out
// https://www.w3.org/TR/did-core/#did-document-properties
package main

import (
	"fmt"
	"os"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
)

func handleError(err error, msg string) {
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("%s: %v", msg, err))
		os.Exit(1)
	}
}
func main() {

	// Create a did:key. This is a specific did using the "key" method
	// GenerateDIDKey takes in a key type value that this library supports and constructs a conformant did:key identifier.
	// To use the private key, it is recommended to re-cast to the associated type.
	// The function returns the associated private key value cast to the generic golang crypto.PrivateKey interface.
	// See more here: https://github.com/TBD54566975/ssi-sdk/blob/main/did/key.go#L51
	_, didKey, err := did.GenerateDIDKey(crypto.Secp256k1)
	handleError(err, "failed to generate key")

	// Expand the DID into a DID Document
	// Expanding is how did:key is resolved in the sdk
	// https://www.w3.org/TR/did-core/#did-document-properties
	didDoc, err := didKey.Expand()
	handleError(err, "failed to expand did:key")

	// print it to stdout
	if dat, err := util.PrettyJSON(didDoc); err != nil {
		handleError(err, "failed to marshal did document")
	} else {
		fmt.Printf("Generated DID document for did:key method:\n%s\n", string(dat)) // Some basic DID information printed out here.
	}

}
