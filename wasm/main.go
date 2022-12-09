//go:build js && wasm

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"syscall/js"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
)

/*
 * This is the glue to bind the functions into javascript so they can be called
 */
func main() {
	done := make(chan struct{})

	// Bind the functions to javascript
	js.Global().Set("sayHello", js.FuncOf(sayHello))
	js.Global().Set("generateKey", js.FuncOf(generateKey))
	js.Global().Set("makeDid", js.FuncOf(makeDid))

	<-done
}

// 1. Simplest function - note we wrap things with js.ValueOf (if a primitive you don't technically need to)
func sayHello(_ js.Value, args []js.Value) interface{} {
	return js.ValueOf("Hello from golang via wasm!")
}

// 2. Calling a ssi-sdk function directly - but returning a plain old string
func generateKey(_ js.Value, args []js.Value) interface{} {

	keyType := args[0].String()
	for _, k := range crypto.GetSupportedKeyTypes() {
		if string(k) == keyType {
			publicKey, _, _ := crypto.GenerateKeyByKeyType(k)
			pubKeyBytes, _ := crypto.PubKeyToBytes(publicKey)
			return js.ValueOf(base64.StdEncoding.EncodeToString(pubKeyBytes))
		}
	}

	return js.ValueOf("Unknown key type")
}

// 3. Returning a richer object, converting to json and then unmarshalling to make it a js object
func makeDid(_ js.Value, args []js.Value) interface{} {

	pubKey, _, _ := crypto.GenerateKeyByKeyType(crypto.Ed25519)
	didKey, _ := did.CreateDIDKey(crypto.Ed25519, pubKey.(ed25519.PublicKey))
	result, _ := didKey.Expand()

	// unmarshall into json bytes, then back into a simple struct for converting to js
	resultBytes, _ := json.Marshal(result)
	var resultObj map[string]interface{}
	json.Unmarshal(resultBytes, &resultObj)
	return js.ValueOf(resultObj)

}
