package did

import (
	gocrypto "crypto"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	UnsupportedDIDError = errors.New("unsupported Method for DID")
)

// Encodes the public key provided
// Using a multi-codec encoding.
func encodePublicKeyWithKeyMultiCodecType(kt crypto.KeyType, pubKey gocrypto.PublicKey) (string, error) {
	if !isSupportedKeyType(kt) {
		return "", errors.Wrap(util.UnsupportedError, "not a supported key type")
	}

	publicKey, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		return "", err
	}

	multiCodec, err := keyTypeToMultiCodec(kt)
	if err != nil {
		return "", err
	}

	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(PeerEncNumBasis, codec)
	if err != nil {
		return "", err
	}

	return encoded, nil
}

func decodeEncodedKey(d string) ([]byte, cryptosuite.LDKeyType, error) {
	encoding, decoded, err := multibase.Decode(d)
	if err != nil {
		return nil, "", err
	}

	if encoding != Base58BTCMultiBase {
		err := fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
		return nil, "", err
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", err
	}
	if n != 2 {
		errMsg := "Error parsing did:key varint"
		return nil, "", errors.New(errMsg)
	}

	pubKeyBytes := decoded[n:]
	multiCodecValue := multicodec.Code(multiCodec)
	switch multiCodecValue {
	case Ed25519MultiCodec:
		return pubKeyBytes, Ed25519VerificationKey2018, nil
	case X25519MultiCodec:
		return pubKeyBytes, X25519KeyAgreementKey2019, nil
	case Secp256k1MultiCodec:
		return pubKeyBytes, EcdsaSecp256k1VerificationKey2019, nil
	case P256MultiCodec, P384MultiCodec, P521MultiCodec, RSAMultiCodec:
		return pubKeyBytes, cryptosuite.JsonWebKey2020, nil
	default:
		err := fmt.Errorf("unknown multicodec for did:key: %d", multiCodecValue)
		return nil, "", err
	}
}

// decode public key with type
func decodePublicKeyWithType(data []byte) ([]byte, cryptosuite.LDKeyType, error) {
	encoding, decoded, err := multibase.Decode(string(data))
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to decode public key for did:peer")
	}

	if encoding != Base58BTCMultiBase {
		err := fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
		return nil, "", err
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", err
	}

	if n != 2 {
		return nil, "", errors.New("Error parsing did:peer varint")
	}

	pubKeyBytes := decoded[n:]
	multiCodecValue := multicodec.Code(multiCodec)
	switch multiCodecValue {
	case Ed25519MultiCodec:
		return pubKeyBytes, Ed25519VerificationKey2020, nil
	case X25519MultiCodec:
		return pubKeyBytes, X25519KeyAgreementKey2020, nil
	case Secp256k1MultiCodec:
		return pubKeyBytes, EcdsaSecp256k1VerificationKey2019, nil
	case P256MultiCodec, P384MultiCodec, P521MultiCodec, RSAMultiCodec:
		return pubKeyBytes, cryptosuite.JsonWebKey2020, nil
	default:
		err := fmt.Errorf("unknown multicodec for did:peer: %d", multiCodecValue)
		return nil, "", err
	}
}

func keyTypeToMultiCodec(kt crypto.KeyType) (multicodec.Code, error) {
	switch kt {
	case crypto.Ed25519:
		return Ed25519MultiCodec, nil
	case crypto.X25519:
		return X25519MultiCodec, nil
	case crypto.SECP256k1:
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
	err := fmt.Errorf("unknown multicodec for key type: %s", kt)
	logrus.WithError(err).Error()
	return 0, err
}
