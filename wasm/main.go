//go:build js && wasm

package main

import (
	"crypto/ed25519"
	"syscall/js"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"encoding/base64"

	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
)

func sayHello() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return js.ValueOf("Hello from golang via wasm!")
	})
}

func simpleAdd() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return args[0].Int() + args[1].Int()
	})
}

func generateKey() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		keyType := args[0].String()
		kt := crypto.KeyType(keyType)
		if !crypto.IsSupportedKeyType(kt) {
			return js.ValueOf("Unknown key type")
		}
		publicKey, _, _ := crypto.GenerateKeyByKeyType(kt)
		pubKeyBytes, _ := crypto.PubKeyToBytes(publicKey)
		return js.ValueOf(base64.StdEncoding.EncodeToString(pubKeyBytes))
	})
}

func makeDid() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		pubKey, _, _ := crypto.GenerateKeyByKeyType(crypto.Ed25519)
		didKey, _ := did.CreateDIDKey(crypto.Ed25519, pubKey.(ed25519.PublicKey))
		result, _ := didKey.Expand()

		// unmarshall into json bytes, then back into a simple struct for converting to js
		resultBytes, _ := json.Marshal(result)
		var resultObj map[string]interface{}
		json.Unmarshal(resultBytes, &resultObj)
		return js.ValueOf(resultObj)
	})
}

func resolveDid() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		didString := args[0].String()
		resolvers := []did.Resolution{did.KeyResolver{}, did.WebResolver{}, did.PKHResolver{}, did.PeerResolver{}}
		resolver, err := did.NewResolver(resolvers...)
		if err != nil {
			return err
		}

		doc, err := resolver.Resolve(didString)
		if err != nil {
			return err
		}

		resultBytes, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		var resultObj map[string]any
		err = json.Unmarshal(resultBytes, &resultObj)
		if err != nil {
			return err
		}

		return js.ValueOf(resultObj)
	})
}

func parseJWTCredential() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {

		cred, err := signing.ParseVerifiableCredentialFromJWT(args[0].String())
		if err != nil {
			return errors.Wrap(err, "could not parse credential from JWT")
		}

		// unmarshall into json bytes, then back into a simple struct for converting to js
		credBytes, err := json.Marshal(cred)
		if err != nil {
			return errors.Wrap(err, "marshal")
		}
		var resultObj map[string]interface{}
		json.Unmarshal(credBytes, &resultObj)
		return js.ValueOf(resultObj)

	})
}

func main() {
	ch := make(chan struct{}, 0)
	js.Global().Set("sayHello", sayHello())
	js.Global().Set("simpleAdd", simpleAdd())
	js.Global().Set("generateKey", generateKey())
	js.Global().Set("makeDid", makeDid())
	js.Global().Set("resolveDid", resolveDid())
	js.Global().Set("parseJWTCredential", parseJWTCredential())
	<-ch
}
