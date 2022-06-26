// This is a very simple application which can create
// a DID and a DID document
// To learn more about the DID, please check out
// https://www.w3.org/TR/did-core/#did-document-properties
// for more information.
package main

import (
	"encoding/json"
	"fmt"

	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
)

// Prints a DID into a JSON format
// The DID is expanded via a DID Document.
// Additional information/properties on the DID Document
// can be found here: https://www.w3.org/TR/did-core/#did-document-properties
func printDIDDDocument(didKey *did.DIDKey) error {

	// Expand the DID into a DID Document
	didDoc, err := didKey.Expand()
	if err != nil {
		return err
	}

	// Marshal out the DID Document into JSON
	if dat, err := json.MarshalIndent(didDoc, "", "   "); err != nil {
		return err
	} else {
		fmt.Printf("Generated DID document:\n%s", string(dat)) // Some basic DID information printed out here.
	}
	return nil
}

// Wraps the GenerateDIDKey function
// Makes a DID, or decentralized identifier.
// The DID syntax and additional information can be found here:
// https://www.w3.org/TR/did-core/#did-syntax
// Seee https://github.com/TBD54566975/ssi-sdk/blob/main/did/key.go#L51
// for more information on how to make it over the SSI-SDK.
func generateDID() (privKey gocrypto.PrivateKey, didKey *did.DIDKey, err error) {
	privKey, didKey, err = did.GenerateDIDKey(crypto.Secp256k1) // Create a DID Key and Private Key from the private key
	return
}

func main() {

	// Generate a DID
	// Check out the method for more information
	var err error
	_, did, err := generateDID()
	if err != nil {
		panic(err)
	}

	// Pretty Print it
	if err = printDIDDDocument(did); err != nil {
		panic(err)
	}
}
