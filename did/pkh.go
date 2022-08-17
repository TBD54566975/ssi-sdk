package did

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"regexp"
	"strings"
)

type (
	DIDPKH  string
	Network string
)

const (
	// DIDPKHPrefix did:pkh prefix
	DIDPKHPrefix = "did:pkh"
)

const (
	Bitcoin  Network = "Bitcoin"
	Ethereum Network = "Ethereum"
	Polygon  Network = "Polygon"
)

var didPkhNetworkPrefixMap = map[Network][]string{
	Bitcoin:  {"bip122:000000000019d6689c085ae165831e93", "EcdsaSecp256k1RecoveryMethod2020"},
	Ethereum: {"eip155:1", "EcdsaSecp256k1RecoveryMethod2020"},
	Polygon:  {"eip155:137", "EcdsaSecp256k1RecoveryMethod2020"},
}

// The following context should be manually inserted into each DID Document. This will likely change
// over time as new verification methods are supported, and general-purpose methods are specified.
var KnownDIDPKHContext, _ = schema.GetKnownSchema("did-pkh-context.json")

// CreateDIDPKHFromNetwork constructs a did:pkh from a network and the networks native address.
func CreateDIDPKHFromNetwork(network Network, address string) (*DIDPKH, error) {
	if _, ok := didPkhNetworkPrefixMap[network]; ok {
		split := strings.Split(didPkhNetworkPrefixMap[network][0], ":")
		return CreateDIDPKH(split[0], split[1], address)
	}

	return nil, fmt.Errorf("unsupported network: %s", string(network))
}

// CreateDIDPKH constructs a did:pkh from a namespace, reference, and account address.
// Reference: did:pkh:namespace:reference:account_address
func CreateDIDPKH(namespace, reference, address string) (*DIDPKH, error) {
	did := DIDPKH(fmt.Sprintf("%s:%s:%s:%s", DIDPKHPrefix, namespace, reference, address))

	if !isValidPKH(did) {
		return nil, fmt.Errorf("PKH DID is not valid: %s", string(did))
	}

	return &did, nil
}

// Expand turns the DID key into a complaint DID Document
func (did DIDPKH) Expand() (*DIDDocument, error) {
	verificationMethod, err := constructPKHVerificationMethod(did)
	if err != nil {
		logrus.WithError(err).Error("could not construct verification method")
		return nil, err
	}

	var KnownDIDPKHContextJson interface{}
	json.Unmarshal([]byte(KnownDIDPKHContext), &KnownDIDPKHContextJson)

	verificationMethodSet := []VerificationMethodSet{
		string(did) + "#blockchainAccountId",
	}

	return &DIDDocument{
		Context:              KnownDIDPKHContextJson,
		ID:                   string(did),
		VerificationMethod:   []VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
		CapabilityInvocation: verificationMethodSet,
	}, nil
}

func constructPKHVerificationMethod(did DIDPKH) (*VerificationMethod, error) {
	if !isValidPKH(did) || did.Parse() == "" {
		errMsg := "PKH DID is not valid"
		return nil, errors.New(errMsg)
	}

	network, _ := GetNetwork(did)
	verificationType := didPkhNetworkPrefixMap[*network][1]

	return &VerificationMethod{
		ID:                  string(did) + "#blockchainAccountId",
		Type:                cryptosuite.LDKeyType(verificationType),
		Controller:          string(did),
		BlockchainAccountId: did.Parse(),
	}, nil
}

// isValidPKH checks if a pkh did is valid based on the following parameters:

// pkh-did    = "did:pkh:" address
// address    = account_id according to [CAIP-10]

// account_id:        chain_id + ":" + account_address
// chain_id:          [-a-z0-9]{3,8}:[-a-zA-Z0-9]{1,32}
// account_address:   [a-zA-Z0-9]{1,64}

// chain_id:    namespace + ":" + reference
// namespace:   [-a-z0-9]{3,8}
// reference:   [-a-zA-Z0-9]{1,32}
func isValidPKH(did DIDPKH) bool {
	split := strings.Split(string(did), ":")

	if len(split) != 5 || (split[0]+":"+split[1]) != DIDPKHPrefix {
		return false
	}

	// namespace
	matched, err := regexp.MatchString(`[-a-z0-9]{3,8}`, split[2])
	if !matched || err != nil {
		return false
	}

	// reference
	matched, err = regexp.MatchString(`[-a-zA-Z0-9]{1,32}`, split[3])
	if !matched || err != nil {
		return false
	}

	// account_address
	matched, err = regexp.MatchString(`[a-zA-Z0-9]{1,64}`, split[4])
	if !matched || err != nil {
		return false
	}

	return true
}

// Parse returns the value without the `did:pkh` prefix
func (did DIDPKH) Parse() string {
	split := strings.Split(string(did), DIDPKHPrefix+":")
	if len(split) != 2 {
		return ""
	}
	return split[1]
}

// GetNetwork returns the network by finding the network prefix in the did
func GetNetwork(didpkh DIDPKH) (*Network, error) {
	for network, prefix := range didPkhNetworkPrefixMap {
		if strings.Contains(string(didpkh), prefix[0]+":") {
			return &network, nil
		}
	}

	return nil, errors.New("network not supported")
}
