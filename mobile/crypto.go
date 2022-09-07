package mobile

import (
	ssi "github.com/TBD54566975/ssi-sdk/crypto"
)

// methods from crypto/models.go

func IsSupportedKeyType(kt string) bool {
	supported := GetSupportedKeyTypes()
	for _, t := range supported {
		if kt == t {
			return true
		}
	}
	return false
}

func GetSupportedKeyTypes() []string {
	return []string{ssi.Ed25519.String(), ssi.X25519.String(), ssi.Secp256k1.String(), ssi.P224.String(), ssi.P256.String(), ssi.P384.String(), ssi.P521.String(), ssi.RSA.String()}
}

func IsSupportedSignatureAlg(sa string) bool {
	supported := GetSupportedSignatureAlgs()
	for _, a := range supported {
		if sa == a {
			return true
		}
	}
	return false
}

func GetSupportedSignatureAlgs() []string {
	return []string{ssi.EdDSA.String(), ssi.ES256K.String(), ssi.ES256.String(), ssi.ES384.String(), ssi.PS256.String()}
}

// methods from crypto/keys.go

type CryptoKeyPair struct {
	PrivKey []byte
	PubKey  []byte
}

func GenerateEd25519Key() (CryptoKeyPair, error) {
	privKey, pubKey, err := ssi.GenerateEd25519Key()
	return CryptoKeyPair{
		PrivKey: privKey,
		PubKey:  pubKey,
	}, err
}

func GenerateX25519Key() (CryptoKeyPair, error) {
	privKey, pubKey, err := ssi.GenerateX25519Key()
	return CryptoKeyPair{
		PrivKey: privKey,
		PubKey:  pubKey,
	}, err
}

type ECDSAKeyPair struct {
	PubKeyX  int64
	PubKeyY  int64
	PrivKeyX int64
	PrivKeyY int64
	PrivKeyD int64
}

func GenerateSecp256k1Key() (ECDSAKeyPair, error) {
	pubKey, privKey, err := ssi.GenerateSecp256k1Key()
	ecdsaPubKey := pubKey.ToECDSA()
	ecdsaPrivKey := privKey.ToECDSA()
	return ECDSAKeyPair{
		PubKeyX:  ecdsaPubKey.X.Int64(),
		PubKeyY:  ecdsaPubKey.Y.Int64(),
		PrivKeyX: ecdsaPrivKey.X.Int64(),
		PrivKeyY: ecdsaPrivKey.Y.Int64(),
		PrivKeyD: ecdsaPrivKey.D.Int64(),
	}, err
}

func GenerateP224Key() (ECDSAKeyPair, error) {
	pubKey, privKey, err := ssi.GenerateP224Key()
	return ECDSAKeyPair{
		PubKeyX:  pubKey.X.Int64(),
		PubKeyY:  pubKey.Y.Int64(),
		PrivKeyX: privKey.X.Int64(),
		PrivKeyY: privKey.Y.Int64(),
		PrivKeyD: privKey.D.Int64(),
	}, err
}

func GenerateP256Key() (ECDSAKeyPair, error) {
	pubKey, privKey, err := ssi.GenerateP256Key()
	return ECDSAKeyPair{
		PubKeyX:  pubKey.X.Int64(),
		PubKeyY:  pubKey.Y.Int64(),
		PrivKeyX: privKey.X.Int64(),
		PrivKeyY: privKey.Y.Int64(),
		PrivKeyD: privKey.D.Int64(),
	}, err
}

func GenerateP384Key() (ECDSAKeyPair, error) {
	pubKey, privKey, err := ssi.GenerateP384Key()
	return ECDSAKeyPair{
		PubKeyX:  pubKey.X.Int64(),
		PubKeyY:  pubKey.Y.Int64(),
		PrivKeyX: privKey.X.Int64(),
		PrivKeyY: privKey.Y.Int64(),
		PrivKeyD: privKey.D.Int64(),
	}, err
}

func GenerateP521Key() (ECDSAKeyPair, error) {
	pubKey, privKey, err := ssi.GenerateP521Key()
	return ECDSAKeyPair{
		PubKeyX:  pubKey.X.Int64(),
		PubKeyY:  pubKey.Y.Int64(),
		PrivKeyX: privKey.X.Int64(),
		PrivKeyY: privKey.Y.Int64(),
		PrivKeyD: privKey.D.Int64(),
	}, err
}

type RSAKeyPair struct {
	PubKeyN  int64
	PubKeyE  int
	PrivKeyD int64
	Primes   []int64
}

func GenerateRSA2048Key() (RSAKeyPair, error) {
	pubKey, privKey, err := ssi.GenerateRSA2048Key()
	var primes []int64
	for _, p := range privKey.Primes {
		primes = append(primes, p.Int64())
	}
	return RSAKeyPair{
		PubKeyE:  pubKey.E,
		PubKeyN:  pubKey.N.Int64(),
		PrivKeyD: privKey.D.Int64(),
		Primes:   primes,
	}, err
}
