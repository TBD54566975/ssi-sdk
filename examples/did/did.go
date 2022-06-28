// This is a very simple application which can create
// a DID and a DID document
// To learn more about the DID, please check out
// https://www.w3.org/TR/did-core/#did-document-properties
// for more information.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
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
		fmt.Printf("Generated DID document:\n%s\n", string(dat)) // Some basic DID information printed out here.
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

	// Create a DID Key and Private Key from the private key
	// GenerateDIDKey takes in a key type value that this library supports and constructs a conformant did:key identifier.
	// To use the private key, it is recommended to re-cast to the associated type.
	// The function returns the associated private key value cast to the generic golang crypto.PrivateKey interface.
	// See more here: https://github.com/TBD54566975/ssi-sdk/blob/main/did/key.go#L51
	privKey, didKey, err = did.GenerateDIDKey(crypto.Secp256k1)
	return
}

// Verifies the DID Document is not corrupted
// Given a private key and a did Key
// FIXME: What's the correct way to determine a tampered DID Document
func validateDIDDocument(privKey gocrypto.PrivateKey, didKey *did.DIDKey) error {

	secp256k1PrivKey, ok := privKey.(secp.PrivateKey)
	if !ok {
		return errors.New("Failed to convert private key")
	}

	// Convert to ECDSA
	// TODO: Better documentation as to why
	ecdsaPrivKey := secp256k1PrivKey.ToECDSA()
	ecdsaPubKey := ecdsaPrivKey.PublicKey
	msg := []byte("hello world")
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivKey, digest[:])
	if err != nil {
		return err
	}

	verified := ecdsa.Verify(&ecdsaPubKey, digest[:], r, s)
	if !verified {
		return errors.New("Could not verify DID")
	}

	return nil
}

func main() {

	if pk, did, err := generateDID(); err != nil {
		panic(err)
	}

	// Print the did to stdout
	if err = printDIDDDocument(did); err != nil {
		panic(err)
	}
	// Verify the document
	if err := validateDIDDocument(pk, did); err != nil {
		fmt.Errorf("Failed to validate DID Document: %s", err.Error())
	} else {
		fmt.Println("Congrats! DID document is not corrupted")
	}

}
