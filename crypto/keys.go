package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/pkg/errors"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/lestrrat-go/jwx/v2/x25519"
)

// GenerateKeyByKeyType creates a brand-new key, returning the public and private key for the given key type
func GenerateKeyByKeyType(kt KeyType) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch kt {
	case Ed25519:
		return GenerateEd25519Key()
	case X25519:
		return GenerateX25519Key()
	case SECP256k1:
		return GenerateSECP256k1Key()
	case SECP256k1ECDSA:
		secpPub, secpPriv, err := GenerateSECP256k1Key()
		if err == nil {
			ecdsaPub := secpPub.ToECDSA()
			ecdsaPriv := secpPriv.ToECDSA()
			return *ecdsaPub, *ecdsaPriv, nil
		}
		return nil, nil, err
	case P224:
		return GenerateP224Key()
	case P256:
		return GenerateP256Key()
	case P384:
		return GenerateP384Key()
	case P521:
		return GenerateP521Key()
	case RSA:
		return GenerateRSA2048Key()
	case Dilithium2:
		return GenerateDilithiumKeyPair(dilithium.Mode2)
	case Dilithium3:
		return GenerateDilithiumKeyPair(dilithium.Mode3)
	case Dilithium5:
		return GenerateDilithiumKeyPair(dilithium.Mode5)
	}
	return nil, nil, fmt.Errorf("unsupported key type: %s", kt)
}

type Option int

const (
	ECDSAMarshalCompressed Option = iota
	ECDSAUnmarshalCompressed
)

// PubKeyToBytes constructs a byte representation of a public key, for a set number of supported key types
func PubKeyToBytes(key crypto.PublicKey, opts ...Option) ([]byte, error) {
	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(crypto.PublicKey)
	}

	switch k := key.(type) {
	case ed25519.PublicKey:
		return k, nil
	case x25519.PublicKey:
		return k, nil
	case secp.PublicKey:
		return k.SerializeCompressed(), nil
	case ecdsa.PublicKey:
		if k.Curve == btcec.S256() {
			x := new(btcec.FieldVal)
			x.SetByteSlice(k.X.Bytes())
			y := new(btcec.FieldVal)
			y.SetByteSlice(k.Y.Bytes())
			return btcec.NewPublicKey(x, y).SerializeCompressed(), nil
		}

		// check if we should marshal the key in compressed form
		if len(opts) == 1 && opts[0] == ECDSAMarshalCompressed {
			return elliptic.MarshalCompressed(k.Curve, k.X, k.Y), nil
		}

		// go from ecdsa public key to bytes
		pk, err := x509.MarshalPKIXPublicKey(&k)
		if err != nil {
			return nil, err
		}
		return pk, nil
	case rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(&k), nil
	case dilithium.PublicKey:
		return k.Bytes(), nil
	case mode2.PublicKey:
		return k.Bytes(), nil
	case mode3.PublicKey:
		return k.Bytes(), nil
	case mode5.PublicKey:
		return k.Bytes(), nil
	}

	return nil, errors.New("unknown public key type; could not convert to bytes")
}

// BytesToPubKey reconstructs a public key given some bytes and a target key type
// It is assumed the key was turned into byte form using the sibling method `PubKeyToBytes`
func BytesToPubKey(keyBytes []byte, kt KeyType, opts ...Option) (crypto.PublicKey, error) {
	switch kt {
	case Ed25519:
		return ed25519.PublicKey(keyBytes), nil
	case X25519:
		return x25519.PublicKey(keyBytes), nil
	case SECP256k1:
		pubKey, err := secp.ParsePubKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *pubKey, nil
	case SECP256k1ECDSA:
		pk, err := secp.ParsePubKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *pk.ToECDSA(), nil
	case P224, P256, P384, P521:
		// check if we should unmarshal the key in compressed form
		if len(opts) == 1 && opts[0] == ECDSAUnmarshalCompressed {
			switch kt {
			case P224:
				x, y := elliptic.UnmarshalCompressed(elliptic.P224(), keyBytes)
				return ecdsa.PublicKey{Curve: elliptic.P224(), X: x, Y: y}, nil
			case P256:
				x, y := elliptic.UnmarshalCompressed(elliptic.P256(), keyBytes)
				return ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
			case P384:
				x, y := elliptic.UnmarshalCompressed(elliptic.P384(), keyBytes)
				return ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, nil
			case P521:
				x, y := elliptic.UnmarshalCompressed(elliptic.P521(), keyBytes)
				return ecdsa.PublicKey{Curve: elliptic.P521(), X: x, Y: y}, nil
			}
		}

		key, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *key.(*ecdsa.PublicKey), nil
	case RSA:
		pubKey, err := x509.ParsePKCS1PublicKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *pubKey, nil
	case Dilithium2:
		return dilithium.Mode2.PublicKeyFromBytes(keyBytes), nil
	case Dilithium3:
		return dilithium.Mode3.PublicKeyFromBytes(keyBytes), nil
	case Dilithium5:
		return dilithium.Mode5.PublicKeyFromBytes(keyBytes), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}
}

// GetKeyTypeFromPrivateKey returns the key type for a private key for known key types
func GetKeyTypeFromPrivateKey(key crypto.PrivateKey) (KeyType, error) {
	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(crypto.PrivateKey)
	}

	switch k := key.(type) {
	case ed25519.PrivateKey:
		return Ed25519, nil
	case x25519.PrivateKey:
		return X25519, nil
	case secp.PrivateKey:
		return SECP256k1, nil
	case ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P224():
			return P224, nil
		case elliptic.P256():
			return P256, nil
		case elliptic.P384():
			return P384, nil
		case elliptic.P521():
			return P521, nil
		case btcec.S256():
			return SECP256k1ECDSA, nil
		default:
			return "", fmt.Errorf("unsupported curve: %s", k.Curve.Params().Name)
		}
	case rsa.PrivateKey:
		return RSA, nil
	case dilithium.PrivateKey:
		mode, err := GetModeFromDilithiumPrivateKey(k)
		if err != nil {
			return "", errors.Wrap(err, "getting dilithium mode from private key")
		}
		switch mode {
		case dilithium.Mode2:
			return Dilithium2, nil
		case dilithium.Mode3:
			return Dilithium3, nil
		case dilithium.Mode5:
			return Dilithium5, nil
		default:
			return "", fmt.Errorf("unknown dilithium mode: %s", mode.Name())
		}
	case mode2.PrivateKey:
		return Dilithium2, nil
	case mode3.PrivateKey:
		return Dilithium3, nil
	case mode5.PrivateKey:
		return Dilithium5, nil
	default:
		return "", errors.New("unknown private key type")
	}
}

// PrivKeyToBytes constructs a byte representation of a private key, for a set number of supported key types
func PrivKeyToBytes(key crypto.PrivateKey) ([]byte, error) {
	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(crypto.PrivateKey)
	}

	switch k := key.(type) {
	case ed25519.PrivateKey:
		return k, nil
	case x25519.PrivateKey:
		return k, nil
	case secp.PrivateKey:
		return k.Serialize(), nil
	case ecdsa.PrivateKey:
		if k.Curve == btcec.S256() {
			scalar := new(btcec.ModNScalar)
			_ = scalar.SetByteSlice(k.D.Bytes())
			privKey := secp.NewPrivateKey(scalar)
			return privKey.Serialize(), nil
		}
		return x509.MarshalECPrivateKey(&k)
	case rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(&k), nil
	case dilithium.PrivateKey:
		return k.Bytes(), nil
	case mode2.PrivateKey:
		return k.Bytes(), nil
	case mode3.PrivateKey:
		return k.Bytes(), nil
	case mode5.PrivateKey:
		return k.Bytes(), nil
	default:
		return nil, errors.New("unknown private key type; could not convert to bytes")
	}
}

// BytesToPrivKey reconstructs a private key given some bytes and a target key type
// It is assumed the key was turned into byte form using the sibling method `PrivKeyToBytes`
func BytesToPrivKey(keyBytes []byte, kt KeyType) (crypto.PrivateKey, error) {
	switch kt {
	case Ed25519:
		return ed25519.PrivateKey(keyBytes), nil
	case X25519:
		return x25519.PrivateKey(keyBytes), nil
	case SECP256k1:
		return *secp.PrivKeyFromBytes(keyBytes), nil
	case SECP256k1ECDSA:
		privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
		return *privKey.ToECDSA(), nil
	case P224, P256, P384, P521:
		privKey, err := x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *privKey, nil
	case RSA:
		privKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *privKey, nil
	case Dilithium2:
		return dilithium.Mode2.PrivateKeyFromBytes(keyBytes), nil
	case Dilithium3:
		return dilithium.Mode3.PrivateKeyFromBytes(keyBytes), nil
	case Dilithium5:
		return dilithium.Mode5.PrivateKeyFromBytes(keyBytes), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}
}

// SECP256k1ECDSAPubKeyToSECP256k1 converts an ecdsa.PublicKey to a secp.PublicKey
func SECP256k1ECDSAPubKeyToSECP256k1(key ecdsa.PublicKey) secp.PublicKey {
	x := new(btcec.FieldVal)
	x.SetByteSlice(key.X.Bytes())
	y := new(btcec.FieldVal)
	y.SetByteSlice(key.Y.Bytes())
	return *btcec.NewPublicKey(x, y)
}

// SECP256k1ECDSASPrivKeyToSECP256k1 converts an ecdsa.PrivateKey to a secp.PrivateKey
func SECP256k1ECDSASPrivKeyToSECP256k1(key ecdsa.PrivateKey) secp.PrivateKey {
	scalar := new(btcec.ModNScalar)
	scalar.SetByteSlice(key.D.Bytes())
	return *secp.NewPrivateKey(scalar)
}

func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func GenerateX25519Key() (x25519.PublicKey, x25519.PrivateKey, error) {
	return x25519.GenerateKey(rand.Reader)
}

func GenerateSECP256k1Key() (secp.PublicKey, secp.PrivateKey, error) {
	privKey, err := secp.GeneratePrivateKey()
	if err != nil {
		return secp.PublicKey{}, secp.PrivateKey{}, err
	}
	pubKey := privKey.PubKey()
	return *pubKey, *privKey, nil
}

func GenerateP224Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P224())
}

func GenerateP256Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P256())
}

func GenerateP384Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P384())
}

func GenerateP521Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P521())
}

func generateECDSAKey(curve elliptic.Curve) (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return ecdsa.PublicKey{}, ecdsa.PrivateKey{}, err
	}
	return privKey.PublicKey, *privKey, nil
}

func GenerateRSA2048Key() (rsa.PublicKey, rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return rsa.PublicKey{}, rsa.PrivateKey{}, err
	}
	return privKey.PublicKey, *privKey, nil
}

// GenerateDilithiumKeyPair generates a new Dilithium key pair for the given mode
func GenerateDilithiumKeyPair(m dilithium.Mode) (dilithium.PublicKey, dilithium.PrivateKey, error) {
	if m == nil {
		return nil, nil, errors.New("dilithium mode cannot be nil")
	}
	pk, sk, err := m.GenerateKey(nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating key for dilithium")
	}
	return pk, sk, nil
}

// GetModeFromDilithiumPrivateKey returns the DilithiumMode from a dilithium.PrivateKey, validating
// the key is a valid private key
func GetModeFromDilithiumPrivateKey(privKey dilithium.PrivateKey) (dilithium.Mode, error) {
	switch len(privKey.Bytes()) {
	case mode2.PrivateKeySize:
		return dilithium.Mode2, nil
	case mode3.PrivateKeySize:
		return dilithium.Mode3, nil
	case mode5.PrivateKeySize:
		return dilithium.Mode5, nil
	default:
		return nil, errors.New("unsupported dilithium mode")
	}
}

// GetModeFromDilithiumPublicKey returns the DilithiumMode from a dilithium.PublicKey, validating
// the key is a valid public key
func GetModeFromDilithiumPublicKey(pubKey dilithium.PublicKey) (dilithium.Mode, error) {
	switch len(pubKey.Bytes()) {
	case mode2.PublicKeySize:
		return dilithium.Mode2, nil
	case mode3.PublicKeySize:
		return dilithium.Mode3, nil
	case mode5.PublicKeySize:
		return dilithium.Mode5, nil
	default:
		return nil, errors.New("unsupported dilithium mode")
	}
}
