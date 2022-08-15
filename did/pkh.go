package did

import (
	gocrypto "crypto"
	"github.com/TBD54566975/ssi-sdk/crypto"
)

type (
	DIDPKH string
)

const (
	Ethereum string = "Ethereum"
)

var blockChainKeyTypeMap = map[string]crypto.KeyType{
	"Ethereum": crypto.Secp256k1,
}

//var blockChainKeyTypeMap map[Blockchain]crypto.KeyType

//blockChainKeyTypeMap = make(map[Blockchain]crypto.KeyType)

// https://github.com/w3c-ccg/did-pkh/blob/90b28ad3c18d63822a8aab3c752302aa64fc9382/did-pkh-method-draft.md
// https://github.com/w3c-ccg/did-pkh/blob/main/test-vectors/did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a.jsonld
// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md
func GenerateDIDPKH(blockchain Blockchain) (gocrypto.PrivateKey, *DIDKey, error) {

	pubKey, privKey, err := crypto.GenerateKeyByKeyType(blockChainKeyTypeMap[blockchain.Ethereum])

}
