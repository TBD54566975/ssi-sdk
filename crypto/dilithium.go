package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/pkg/errors"
)

type (
	DilithiumMode string
)

func (m DilithiumMode) String() string {
	return string(m)
}

const (
	Dilithium2 DilithiumMode = "Dilithium2"
	Dilithium3 DilithiumMode = "Dilithium3"
	Dilithium5 DilithiumMode = "Dilithium5"
)

// GenerateDilithiumKeyPair generates a new Dilithium key pair for the given mode
func GenerateDilithiumKeyPair(m DilithiumMode) (dilithium.PublicKey, dilithium.PrivateKey, error) {
	mode := dilithium.ModeByName(m.String())
	if mode == nil {
		return nil, nil, fmt.Errorf("unsupported dilithium mode: %s", m)
	}
	pk, sk, err := mode.GenerateKey(nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not generate key for dilithium")
	}
	return pk, sk, nil
}

// DilithiumSigner is a signer for Dilithium signatures, wrapping the dilithium.Mode, PublicKey, PrivateKey, and KID
type DilithiumSigner struct {
	KID  string
	mode dilithium.Mode
	dilithium.PublicKey
	dilithium.PrivateKey
}

// NewDilithiumSigner returns a new DilithiumSigner, validating the private key is a valid private key
func NewDilithiumSigner(kid string, privKey dilithium.PrivateKey) (*DilithiumSigner, error) {
	mode, err := GetModeFromDilithiumPrivateKey(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "getting dilithium mode from private key")
	}
	publicKey := privKey.Public().(dilithium.PublicKey)
	if _, err = GetModeFromDilithiumPublicKey(publicKey); err != nil {
		return nil, errors.Wrap(err, "getting dilithium mode from public key")
	}
	m := DilithiumModeToMode(mode)
	return &DilithiumSigner{
		KID:        kid,
		mode:       m,
		PublicKey:  publicKey,
		PrivateKey: privKey,
	}, nil
}

// GetKeyID returns the KID of the DilithiumSigner
func (s *DilithiumSigner) GetKeyID() string {
	return s.KID
}

// Sign signs the message with the DilithiumSigner's private key
func (s *DilithiumSigner) Sign(message []byte) []byte {
	return s.mode.Sign(s.PrivateKey, message)
}

// DilithiumVerifier is a verifier for Dilithium signatures, wrapping the dilithium.Mode, PublicKey, and KID
type DilithiumVerifier struct {
	KID  string
	mode dilithium.Mode
	dilithium.PublicKey
}

// NewDilithiumVerifier returns a new DilithiumVerifier, validating the public key is a valid public key
func NewDilithiumVerifier(kid string, pubKey dilithium.PublicKey) (*DilithiumVerifier, error) {
	// verify the mode can be extracted from the PK, meaning it's a valid PK
	mode, err := GetModeFromDilithiumPublicKey(pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "getting dilithium mode from public key")
	}
	m := DilithiumModeToMode(mode)
	return &DilithiumVerifier{
		KID:       kid,
		mode:      m,
		PublicKey: pubKey,
	}, nil
}

func (s *DilithiumVerifier) Verify(message, signature []byte) bool {
	return s.mode.Verify(s.PublicKey, message, signature)
}

// DilithiumModeToMode converts a DilithiumMode (our representation) to a dilithium.Mode (lib representation)
func DilithiumModeToMode(m DilithiumMode) dilithium.Mode {
	switch m {
	case Dilithium2:
		return dilithium.Mode2
	case Dilithium3:
		return dilithium.Mode3
	case Dilithium5:
		return dilithium.Mode5
	default:
		return nil
	}
}

// GetModeFromDilithiumPrivateKey returns the DilithiumMode from a dilithium.PrivateKey, validating
// the key is a valid private key
func GetModeFromDilithiumPrivateKey(privKey dilithium.PrivateKey) (DilithiumMode, error) {
	switch len(privKey.Bytes()) {
	case mode2.PrivateKeySize:
		return Dilithium2, nil
	case mode3.PrivateKeySize:
		return Dilithium3, nil
	case mode5.PrivateKeySize:
		return Dilithium5, nil
	default:
		return "", errors.New("unsupported dilithium mode")
	}
}

// GetModeFromDilithiumPublicKey returns the DilithiumMode from a dilithium.PublicKey, validating
// the key is a valid public key
func GetModeFromDilithiumPublicKey(pubKey dilithium.PublicKey) (DilithiumMode, error) {
	switch len(pubKey.Bytes()) {
	case mode2.PublicKeySize:
		return Dilithium2, nil
	case mode3.PublicKeySize:
		return Dilithium3, nil
	case mode5.PublicKeySize:
		return Dilithium5, nil
	default:
		return "", errors.New("unsupported dilithium mode")
	}
}
