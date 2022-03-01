package did

import (
	gocrypto "crypto"
	"fmt"

	"github.com/pkg/errors"

	"github.com/TBD54566975/did-sdk/crypto"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

type DIDKey string

const (
	// Base58BTCMultiBase Base58BTC https://github.com/multiformats/go-multibase/blob/master/multibase.go
	Base58BTCMultiBase = multibase.Base58BTC

	// Multicodec reference https://github.com/multiformats/multicodec/blob/master/table.csv

	Ed25519MultiCodec   = multicodec.Ed25519Pub
	X25519MultiCodec    = multicodec.X25519Pub
	Secp256k1MultiCodec = multicodec.Secp256k1Pub
	P256MultiCodec      = multicodec.P256Pub
	P384MultiCodec      = multicodec.P384Pub
	P521MultiCodec      = multicodec.P521Pub
	RSAMultiCodec       = multicodec.RsaPub

	// DIDKeyPrefix did:key prefix
	DIDKeyPrefix = "did:key"
)

func GenerateDIDKey(kt crypto.KeyType) (gocrypto.PrivateKey, *DIDKey, error) {
	if !isSupportedKeyType(kt) {
		return nil, nil, fmt.Errorf("unsupported did:key type: %s", kt)
	}

	pubKey, privKey, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not generate key for did:key")
	}

	pubKeyBytes, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		return nil, nil, err
	}

	didKey, err := CreateDIDKey(kt, pubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	return privKey, didKey, err
}

// CreateDIDKey constructs a did:key from a specific key type and its corresponding public key
// This method does not attempt to validate that the provided public key is of the specified key type.
// A safer method is `GenerateDIDKey` which handles key generation based on the provided key type.
func CreateDIDKey(kt crypto.KeyType, publicKey []byte) (*DIDKey, error) {
	if !isSupportedKeyType(kt) {
		return nil, fmt.Errorf("unsupported did:key type: %s", kt)
	}

	// did:key:<multibase encoded, multicodec identified, public key>
	multiCodec, err := keyTypeToMultiCodec(kt)
	if err != nil {
		return nil, err
	}
	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(Base58BTCMultiBase, codec)
	if err != nil {
		return nil, err
	}
	did := DIDKey(fmt.Sprintf("%s:%s", DIDKeyPrefix, encoded))
	return &did, nil
}

func (d DIDKey) Expand() string {
	return ""
}

func keyTypeToMultiCodec(kt crypto.KeyType) (multicodec.Code, error) {
	switch kt {
	case crypto.Ed25519:
		return Ed25519MultiCodec, nil
	case crypto.X25519:
		return X25519MultiCodec, nil
	case crypto.Secp256k1:
		return Secp256k1MultiCodec, nil
	case crypto.P256:
		return P256MultiCodec, nil
	case crypto.P384:
		return P384MultiCodec, nil
	case crypto.P521:
		return P521MultiCodec, nil
	case crypto.RSA:
		return RSAMultiCodec, nil
	}
	return 0, fmt.Errorf("unknown multicodec for key type: %s", kt)
}

func isSupportedKeyType(kt crypto.KeyType) bool {
	keyTypes := GetSupportedDIDKeyTypes()
	for _, t := range keyTypes {
		if t == kt {
			return true
		}
	}
	return false
}

func GetSupportedDIDKeyTypes() []crypto.KeyType {
	return []crypto.KeyType{crypto.Ed25519, crypto.X25519, crypto.Secp256k1, crypto.P256, crypto.P384, crypto.P521, crypto.RSA}
}
