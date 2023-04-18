package example

import (
	"context"
	gocrypto "crypto"
	"errors"
	"fmt"
	"sync"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
)

// SimpleWallet is a sample wallet
// This would NOT be how it would be stored in production, but serves for demonstrative purposes
// This holds the assigned DIDs, their associated private keys, and VCs
type SimpleWallet struct {
	vcs  map[string]string
	dids map[string][]WalletKeys
	mux  *sync.Mutex
}

type WalletKeys struct {
	ID  string
	Key gocrypto.PrivateKey
}

func NewSimpleWallet() *SimpleWallet {
	return &SimpleWallet{
		vcs:  make(map[string]string),
		mux:  new(sync.Mutex),
		dids: make(map[string][]WalletKeys),
	}
}

func (s *SimpleWallet) AddDID(id string) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.dids[id]; ok {
		return errors.New("already an entry")
	}
	s.dids[id] = make([]WalletKeys, 0)
	return nil
}

func (s *SimpleWallet) GetDIDs() []string {
	s.mux.Lock()
	defer s.mux.Unlock()
	var dids []string
	for d := range s.dids {
		dids = append(dids, d)
	}
	return dids
}

// AddPrivateKey Adds a Private Key to a wallet
func (s *SimpleWallet) AddPrivateKey(id, kid string, key gocrypto.PrivateKey) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	walletKeys, ok := s.dids[id]
	if !ok {
		return fmt.Errorf("did<%s> not found", id)
	}
	for _, k := range walletKeys {
		if k.ID == kid {
			return fmt.Errorf("key<%s> already exists", kid)
		}
	}
	walletKeys = append(walletKeys, WalletKeys{
		ID:  kid,
		Key: key,
	})
	s.dids[id] = walletKeys
	return nil
}

func (s *SimpleWallet) GetKey(kid string) (string, gocrypto.PrivateKey, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	for _, d := range s.dids {
		for _, k := range d {
			if k.ID == kid {
				return k.ID, k.Key, nil
			}
		}
	}
	return "", nil, fmt.Errorf("key<%s> not found", kid)
}

func (s *SimpleWallet) GetKeysForDID(id string) ([]WalletKeys, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if keys, ok := s.dids[id]; ok {
		return keys, nil
	}
	return nil, fmt.Errorf("id<%s> not found", id)
}

func (s *SimpleWallet) AddCredentialJWT(credID, cred string) error {
	if s.mux == nil {
		return errors.New("no mux for wallet")
	}

	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.vcs[credID]; ok {
		return fmt.Errorf("duplicate credential<%s>; could not add", credID)
	}
	s.vcs[credID] = cred
	return nil
}

// Init stores a DID for a particular user and adds it to the registry
func (s *SimpleWallet) Init(didMethod did.Method) error {
	var privKey gocrypto.PrivateKey
	var pubKey gocrypto.PublicKey

	var didStr string
	var kid string
	var err error
	switch didMethod {
	case did.PeerMethod:
		kt := crypto.Ed25519
		pubKey, privKey, err = crypto.GenerateKeyByKeyType(kt)
		if err != nil {
			return err
		}
		didPeer, err := did.PeerMethod0{}.Generate(kt, pubKey)
		if err != nil {
			return err
		}
		didStr = didPeer.String()
		resolvedPeer, err := did.PeerResolver{}.Resolve(context.Background(), didPeer.String())
		if err != nil {
			return err
		}
		kid = resolvedPeer.VerificationMethod[0].ID
	case did.KeyMethod:
		var didKey *did.DIDKey
		privKey, didKey, err = did.GenerateDIDKey(crypto.Ed25519)
		if err != nil {
			return err
		}
		didStr = didKey.String()
		expanded, err := didKey.Expand()
		if err != nil {
			return err
		}
		kid = expanded.VerificationMethod[0].ID
	default:
		return fmt.Errorf("unsupported did method<%s>", didMethod)
	}

	WriteNote(fmt.Sprintf("DID for holder is: %s", didStr))
	if err = s.AddDID(didStr); err != nil {
		return err
	}
	WriteNote(fmt.Sprintf("DID stored in wallet"))
	if err = s.AddPrivateKey(didStr, kid, privKey); err != nil {
		return err
	}
	WriteNote(fmt.Sprintf("Private Key stored with wallet"))
	return nil
}

func (s *SimpleWallet) Size() int {
	return len(s.vcs)
}
