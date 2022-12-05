package example

import (
	gocrypto "crypto"
	"errors"
	"fmt"
	"sync"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
)

// SimpleWallet is a sample wallet
// This would NOT be how it would be stored in production, but serves for demonstrative purposes
// This holds the assigned DIDs, their associated private keys, and VCs
type SimpleWallet struct {
	vcs  map[string]credential.VerifiableCredential
	keys map[string]gocrypto.PrivateKey
	dids map[string]string
	mux  *sync.Mutex
}

func NewSimpleWallet() *SimpleWallet {
	return &SimpleWallet{
		vcs:  make(map[string]credential.VerifiableCredential),
		mux:  new(sync.Mutex),
		dids: make(map[string]string),
		keys: make(map[string]gocrypto.PrivateKey),
	}
}

// AddPrivateKey Adds a Private Key to a wallet
func (s *SimpleWallet) AddPrivateKey(k string, key gocrypto.PrivateKey) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.keys[k]; ok {
		return errors.New("already an entry")
	}
	s.keys[k] = key
	return nil
}

func (s *SimpleWallet) AddDIDKey(k string, key string) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.dids[k]; ok {
		return errors.New("already an entry")
	}
	s.dids[k] = key
	return nil
}

func (s *SimpleWallet) GetDID(k string) (string, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if v, ok := s.dids[k]; ok {
		return v, nil
	}
	return "", errors.New("not found")
}

func (s *SimpleWallet) AddCredentials(cred credential.VerifiableCredential) error {
	if s.mux == nil {
		return errors.New("no mux for wallet")
	}

	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.vcs[cred.ID]; ok {
		return fmt.Errorf("duplicate credential<%s>; could not add", cred.ID)
	}
	s.vcs[cred.ID] = cred
	return nil
}

// Init stores a DID for a particular user and adds it to the registry
func (s *SimpleWallet) Init(keyType string) error {
	var privKey gocrypto.PrivateKey
	var pubKey gocrypto.PublicKey

	var didStr string
	var err error

	if keyType == did.DIDPeerPrefix {
		kt := crypto.Ed25519
		pubKey, privKey, err = crypto.GenerateKeyByKeyType(kt)
		if err != nil {
			return err
		}
		didk, err := did.PeerMethod0{}.Generate(kt, pubKey)
		if err != nil {
			return err
		}
		didStr = didk.String()
	} else {
		var didKey *did.DIDKey
		privKey, didKey, err = did.GenerateDIDKey(crypto.SECP256k1)
		if err != nil {
			return err
		}
		didStr = string(*didKey)
	}

	WriteNote(fmt.Sprintf("DID for holder is: %s", didStr))
	if err := s.AddPrivateKey("main", privKey); err != nil {
		return err
	}
	WriteNote(fmt.Sprintf("Private Key stored with wallet"))
	if err := s.AddDIDKey("main", string(didStr)); err != nil {
		return err
	}
	WriteNote(fmt.Sprintf("DID Key stored in wallet"))

	return nil
}

func (s *SimpleWallet) Size() int {
	return len(s.vcs)
}
