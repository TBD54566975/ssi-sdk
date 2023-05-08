package peer

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolver"
)

type PeerResolver struct{}

var _ resolver.Resolver = (*PeerResolver)(nil)

func (PeerResolver) Resolve(_ context.Context, id string, opts ...resolver.ResolutionOption) (*resolver.ResolutionResult, error) {
	if !strings.HasPrefix(id, DIDPeerPrefix) {
		return nil, fmt.Errorf("not a did:peer DID: %s", id)
	}

	didPeer := DIDPeer(id)
	if len(didPeer) < len(DIDPeerPrefix)+2 {
		return nil, errors.New("did is too short")
	}

	m := string(didPeer[9])
	if peerMethodAvailable(m) {
		switch m {
		case "0":
			return PeerMethod0{}.resolve(didPeer, opts)
		case "1":
			return PeerMethod1{}.resolve(didPeer, opts)
		case "2":
			return PeerMethod2{}.resolve(didPeer, opts)
		default:
			return nil, fmt.Errorf("%s method not supported", m)
		}
	}
	return nil, fmt.Errorf("could not resolve peer DID: %s", id)
}

func (PeerResolver) Methods() []did.Method {
	return []did.Method{did.PeerMethod}
}
