package peer

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
)

func IsSupportedDIDPeerType(kt crypto.KeyType) bool {
	keyTypes := GetSupportedDIDPeerTypes()
	for _, t := range keyTypes {
		if t == kt {
			return true
		}
	}
	return false
}

func GetSupportedDIDPeerTypes() []crypto.KeyType {
	return []crypto.KeyType{crypto.Ed25519, crypto.X25519, crypto.SECP256k1,
		crypto.P256, crypto.P384, crypto.P521, crypto.RSA}
}
