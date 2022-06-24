// This is a very simple application which can create
// a DID, DID Document, and a VC.
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

	didDoc, err := didKey.Expand() // Expand the DID into a DID Document
	if err != nil {
		return err
	}

	dat, err := json.MarshalIndent(didDoc, "", "   ") // Marshal out the DID Document into JSON
	if err != nil {
		return err
	}

	fmt.Println(string(dat)) // Some basic DID information printed out here.
	return nil
}

// Wraps the GenerateDIDKey function
// Makes a DID, or decentralized identifier.
// The DID syntax and additional information can be found here:
// https://www.w3.org/TR/did-core/#did-syntax
// Seee https://github.com/TBD54566975/ssi-sdk/blob/main/did/key.go#L51
// for more information on how to make it over the SSI-SDK.
func generateDID() (privKey gocrypto.PrivateKey, didKey *did.DIDKey, error error) {
	privKey, didKey, err := did.GenerateDIDKey(crypto.Secp256k1) // Create a DID Key and Private Key from the private key
	if err != nil {
		return nil, nil, err
	}
	return privKey, didKey, nil
}

func main() {

	// make the DID
	_, did, err := generateDID()
	if err != nil {
		panic(err)
	}

	// Print it
	err = printDIDDDocument(did)
	if err != nil {
		panic(err)
	}

}
