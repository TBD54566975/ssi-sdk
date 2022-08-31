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

// A sample wallet
// This would NOT be how it would be stored in production
// But serves for demonstrative purposes
// This holds the assigned dids
// private keys
// and vCs
type SimpleWallet struct {
	vcs  map[string]credential.VerifiableCredential
	keys map[string]gocrypto.PrivateKey
	dids map[string]string
	mux  *sync.Mutex
}

func NewSimpleWallet() *SimpleWallet {
	return &SimpleWallet{
		vcs:  make(map[string]credential.VerifiableCredential),
		mux:  &sync.Mutex{},
		dids: make(map[string]string),
		keys: make(map[string]gocrypto.PrivateKey),
	}
}

// Adds a Private Key to a wallet
func (s *SimpleWallet) AddPrivateKey(k string, key gocrypto.PrivateKey) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.keys[k]; !ok {
		s.keys[k] = key
	} else {
		return errors.New("Already an entry")
	}
	return nil
}

func (s *SimpleWallet) AddDIDKey(k string, key string) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.dids[k]; !ok {
		s.dids[k] = key
	} else {
		return errors.New("Already an entry")
	}
	return nil
}

func (s *SimpleWallet) GetDID(k string) (string, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if v, ok := s.dids[k]; ok {
		return v, nil
	} else {
		return "", errors.New("Not found")
	}
	return "", nil
}

func (s *SimpleWallet) AddCredentials(cred credential.VerifiableCredential) error {

	if s.mux == nil {
		return errors.New("no mux for wallet")
	}

	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.vcs[cred.ID]; !ok {
		s.vcs[cred.ID] = cred
	} else {
		return errors.New("Duplicate Credential. Could not add.")
	}
	return nil
}

// In the simple wallet
// Stores a DID for a particular user and
// adds it to the registry
func (s *SimpleWallet) Init(keyType string) error {

	s.mux.Lock() // TODO: remove the muxes?
	s.mux.Unlock()

	var privKey gocrypto.PrivateKey
	var pubKey gocrypto.PublicKey

	var didStr string
	var err error

	if keyType == did.PeerMethodPrefix {
		kt := crypto.Ed25519
		pubKey, privKey, err = crypto.GenerateKeyByKeyType(kt)
		if err != nil {
			return err
		}
		didk, err := did.PeerMethod0{}.Generate(kt, pubKey)
		if err != nil {
			return err
		}
		didStr = didk.ToString()
	} else {
		var didKey *did.DIDKey
		privKey, didKey, err = did.GenerateDIDKey(crypto.Secp256k1)
		if err != nil {
			return err
		}
		didStr = string(*didKey)
	}

	WriteNote(fmt.Sprintf("DID for holder is: %s", didStr))
	s.AddPrivateKey("main", privKey)
	WriteNote(fmt.Sprintf("Private Key stored with wallet"))
	s.AddDIDKey("main", string(didStr))
	WriteNote(fmt.Sprintf("DID Key stored in wallet"))

	return nil
}

func (s *SimpleWallet) Size() int {
	return len(s.vcs)
}
