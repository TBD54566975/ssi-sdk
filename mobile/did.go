package mobile

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/goccy/go-json"
	"github.com/sirupsen/logrus"
)

type GenerateDIDKeyResult struct {
	DID string         `json:"did"`
	JWK map[string]any `json:"jwk"`
}

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
