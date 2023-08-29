package mobile

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/goccy/go-json"
	"github.com/sirupsen/logrus"
)

// GetSupportedKeyTypes returns a list of supported key types as string values
func GetSupportedKeyTypes() []string {
	keyTypes := make([]string, len(crypto.GetSupportedKeyTypes()))
	for _, kt := range crypto.GetSupportedKeyTypes() {
		keyTypes = append(keyTypes, string(kt))
	}
	return keyTypes
}

type GenerateDIDKeyResult struct {
	DID string         `json:"did"`
	JWK map[string]any `json:"jwk"`
}

// GenerateDIDKey generates a new DID key and returns a JSON representation of GenerateDIDKeyResult
func GenerateDIDKey(kt string) ([]byte, error) {
	privateKey, didKey, err := key.GenerateDIDKey(crypto.KeyType(kt))
	if err != nil {
		logrus.WithError(err).Error("failed to generate did key")
		return nil, err
	}

	expanded, err := didKey.Expand()
	if err != nil {
		logrus.WithError(err).Error("failed to expand did key")
		return nil, err
	}

	_, jwkPrivateKey, err := jwx.PrivateKeyToPrivateKeyJWK(expanded.VerificationMethod[0].ID, privateKey)
	if err != nil {
		logrus.WithError(err).Error("failed to convert private key to jwk")
		return nil, err
	}

	jwkBytes, err := json.Marshal(jwkPrivateKey)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal jwk")
		return nil, err
	}

	var jwk map[string]any
	if err = json.Unmarshal(jwkBytes, &jwk); err != nil {
		logrus.WithError(err).Error("failed to unmarshal jwk")
		return nil, err
	}

	result := GenerateDIDKeyResult{
		DID: didKey.String(),
		JWK: jwk,
	}
	return json.Marshal(result)
}

type CreateDIDKeyRequest struct {
	KeyType      string         `json:"keyType"`
	PublicKeyJWK map[string]any `json:"publicKeyJwk"`
}

type CreateDIDKeyResult struct {
	DID string `json:"did"`
}

// CreateDIDKey creates a new DID key from an existing public key, accepting a JSON representation of CreateDIDKeyRequest
// and returns a JSON representation of CreateDIDKeyResult which contains the DID of the newly created key as a string
func CreateDIDKey(requestBytes []byte) ([]byte, error) {
	var request CreateDIDKeyRequest
	if err := json.Unmarshal(requestBytes, &request); err != nil {
		logrus.WithError(err).Error("failed to unmarshal request")
		return nil, err
	}

	// transform the json representation of the public key jwk into a public key
	publicKeyBytes, err := json.Marshal(request.PublicKeyJWK)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal public key jwk")
		return nil, err
	}
	var publicKeyJWK jwx.PublicKeyJWK
	if err = json.Unmarshal(publicKeyBytes, &publicKeyJWK); err != nil {
		logrus.WithError(err).Error("failed to unmarshal public key jwk")
		return nil, err
	}
	publicKey, err := publicKeyJWK.ToPublicKey()
	if err != nil {
		logrus.WithError(err).Error("failed to convert public key jwk to public key")
		return nil, err
	}
	pubKeyBytes, err := crypto.PubKeyToBytes(publicKey)
	if err != nil {
		logrus.WithError(err).Error("failed to convert public key to bytes")
		return nil, err
	}

	didKey, err := key.CreateDIDKey(crypto.KeyType(request.KeyType), pubKeyBytes)
	if err != nil {
		logrus.WithError(err).Error("failed to create did key")
		return nil, err
	}

	result := CreateDIDKeyResult{DID: didKey.String()}
	return json.Marshal(result)
}

type Document struct {
	DIDDocument map[string]any `json:"didDocument"`
}

// ExpandDIDKey expands a DID key string and returns a JSON representation of the expanded key
func ExpandDIDKey(didKey string) ([]byte, error) {
	expanded, err := key.DIDKey(didKey).Expand()
	if err != nil {
		logrus.WithError(err).Error("failed to expand did key")
		return nil, err
	}

	expandedBytes, err := json.Marshal(expanded)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal expanded did key")
		return nil, err
	}

	var didDocJSON map[string]any
	if err = json.Unmarshal(expandedBytes, &didDocJSON); err != nil {
		logrus.WithError(err).Error("failed to unmarshal did document")
		return nil, err
	}

	document := Document{DIDDocument: didDocJSON}
	return json.Marshal(document)
}
