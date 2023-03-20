package ion

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	sdkcrypto "github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/goccy/go-json"
	"github.com/gowebpki/jcs"
	"github.com/multiformats/go-multihash"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// HashEncode hashes given data according to the protocol's hashing process
// https://identity.foundation/sidetree/spec/#hashing-process
func HashEncode(data []byte) (string, error) {
	hashed, err := Multihash(data)
	if err != nil {
		return "", err
	}
	return Encode(hashed), nil
}

// Hash hashes given data according to the protocol's hashing process; not multihashed
func Hash(data []byte) []byte {
	hashed := sha256.Sum256(data)
	return hashed[:]
}

// Multihash https://multiformats.io/multihash/
func Multihash(data []byte) ([]byte, error) {
	// first hash using the given hashing algorithm
	hashed := sha256.Sum256(data)

	// next encode as a mulithash
	multiHashed, err := multihash.Encode(hashed[:], multihash.SHA2_256)
	if err != nil {
		logrus.WithError(err).Error("could not multi-hash the given data")
		return nil, err
	}
	return multiHashed, nil
}

// Encode encodes according to the encoding scheme of the sidetree spec
func Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// EncodeString encodes a string according to the encoding scheme of the sidetree spec
func EncodeString(data string) string {
	return Encode([]byte(data))
}

// EncodeAny encodes any according to the encoding scheme of the sidetree spec
func EncodeAny(data any) (string, error) {
	anyBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return Encode(anyBytes), nil
}

// Decode decodes according to the encoding scheme of the sidetree spec
func Decode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

// Canonicalize transforms JSON according to the protocol's JSON Canonicalization Scheme
// https://identity.foundation/sidetree/spec/#json-canonicalization-scheme
func Canonicalize(data []byte) ([]byte, error) {
	return jcs.Transform(data)
}

// CanonicalizeAny transforms JSON according to the protocol's JSON Canonicalization Scheme
// https://identity.foundation/sidetree/spec/#json-canonicalization-scheme
func CanonicalizeAny(data any) ([]byte, error) {
	anyBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return Canonicalize(anyBytes)
}

// Commit creates a public key commitment according to the steps defined in the protocol
// https://identity.foundation/sidetree/spec/#public-key-commitment-scheme
func Commit(key sdkcrypto.PublicKeyJWK) (reveal, commitment string, err error) {
	// 1. Encode the public key into the form of a valid JWK.
	gotJWK, err := sdkcrypto.JWKFromPublicKeyJWK(key)
	if err != nil {
		return "", "", err
	}

	// 2. Canonicalize the JWK encoded public key using the implementation’s JSON_CANONICALIZATION_SCHEME.
	canonicalKey, err := CanonicalizeAny(gotJWK)
	if err != nil {
		logrus.WithError(err).Error("could not canonicalize JWK")
		return "", "", err
	}

	// 3. Use the implementation’s HASH_PROTOCOL to Multihash the canonicalized public key to generate the REVEAL_VALUE,
	// then Multihash the resulting Multihash value again using the implementation’s HASH_PROTOCOL to produce
	// the public key commitment.
	intermediateHash := Hash(canonicalKey)
	reveal, err = HashEncode(canonicalKey)
	if err != nil {
		logrus.WithError(err).Error("could not generate reveal value")
		return "", "", err
	}
	commitment, err = HashEncode(intermediateHash)
	if err != nil {
		logrus.WithError(err).Error("could not generate commitment value")
		return "", "", err
	}

	return reveal, commitment, nil
}

type BTCSignerVerifier struct {
	publicKey  *btcec.PublicKey
	privateKey *btcec.PrivateKey
}

// NewBTCSignerVerifier creates a new signer/verifier for signatures suited for the BTC blockchain
func NewBTCSignerVerifier(privateKey sdkcrypto.PrivateKeyJWK) (*BTCSignerVerifier, error) {
	privateKeyBytes, err := json.Marshal(privateKey)
	if err != nil {
		return nil, err
	}
	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)
	return &BTCSignerVerifier{
		publicKey:  pubKey,
		privateKey: privKey,
	}, nil
}

// GetJWSHeader returns the default JWS header for the BTC signer
func (*BTCSignerVerifier) GetJWSHeader() map[string]any {
	return map[string]any{
		"alg": "ES256K",
	}
}

// Sign signs the given data according to Bitcoin's signing process
func (s *BTCSignerVerifier) Sign(data []byte) ([]byte, error) {
	messageHash := Hash(data)
	signature := ecdsa.Sign(s.privateKey, messageHash)
	return toCompactHex(signature)
}

func toCompactHex(signature *ecdsa.Signature) ([]byte, error) {
	r := reflect.ValueOf(signature).Elem().FieldByName("r")
	s := reflect.ValueOf(signature).Elem().FieldByName("s")

	gotR := getUnexportedField(r).(secp256k1.ModNScalar)
	gotS := getUnexportedField(s).(secp256k1.ModNScalar)

	reconstructed := ecdsa.NewSignature(&gotR, &gotS)
	if !signature.IsEqual(reconstructed) {
		return nil, errors.New("could not reconstruct signature")
	}

	// convert r and s to big ints and then to 32 byte hex strings
	rBytes := gotR.Bytes()
	sBytes := gotS.Bytes()
	rBigInt := new(big.Int).SetBytes(rBytes[:])
	sBigInt := new(big.Int).SetBytes(sBytes[:])

	return hexToBytes(numTo32bStr(rBigInt) + numTo32bStr(sBigInt))
}

func hexToBytes(hex string) ([]byte, error) {
	if hex == "" {
		return nil, errors.New("hexToBytes: expected non-empty string")
	}
	if len(hex)%2 != 0 {
		return nil, errors.New("hexToBytes: received invalid unpadded hex")
	}
	b := make([]byte, len(hex)/2)
	for i := 0; i < len(b); i++ {
		j := i * 2
		hexByte := hex[j : j+2]
		byteValue, err := strconv.ParseUint(hexByte, 16, 8)
		if err != nil {
			return nil, errors.New("Invalid byte sequence")
		}
		b[i] = byte(byteValue)
	}
	return b, nil
}

func numTo32bStr(num *big.Int) string {
	hexStr := fmt.Sprintf("%x", num)
	return fmt.Sprintf("%064s", hexStr)
}

func getUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

type Signature struct {
	r secp256k1.ModNScalar
	s secp256k1.ModNScalar
}

// Verify verifies the given data according to Bitcoin's verification process
func (s *BTCSignerVerifier) Verify(data, signature []byte) (bool, error) {
	// goecdsa.Si()
	// messageHash := Hash(data)
	// return verified, nil
	return false, nil
}

// SignJWT signs the given data according to the protocol's JWT signing process,
// creating a compact JWS in a JWT
func (s *BTCSignerVerifier) SignJWT(data any) (string, error) {
	encodedHeader, err := EncodeAny(s.GetJWSHeader())
	if err != nil {
		logrus.WithError(err).Error("could not encode header")
		return "", nil
	}
	encodedPayload, err := EncodeAny(data)
	if err != nil {
		logrus.WithError(err).Error("could not encode payload")
		return "", nil
	}

	signingContent := encodedHeader + "." + encodedPayload
	contentHash := Hash([]byte(signingContent))

	signed, err := s.Sign(contentHash)
	if err != nil {
		return "", nil
	}
	encodedSignature := Encode([]byte(signed))

	compactJWS := encodedHeader + "." + encodedPayload + "." + encodedSignature
	return compactJWS, nil
}

// VerifyJWS verifies the given data according to the protocol's JWS verification process
func (s *BTCSignerVerifier) VerifyJWS(jws string) (bool, error) {
	jwsParts := strings.Split(jws, ".")
	if len(jwsParts) != 3 {
		return false, fmt.Errorf("invalid JWS: %s", jws)
	}

	signingContent := jwsParts[0] + "." + jwsParts[1]
	contentHash := Hash([]byte(signingContent))

	decodedSignature, err := Decode(jwsParts[2])
	if err != nil {
		return false, errors.Wrap(err, "could not decode signature")
	}

	return s.Verify(contentHash, decodedSignature)
}
