package did

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"regexp"
	"strings"
)

type (
	DIDPKH  string
	Network string
)

const (
	// DIDPKHPrefix did:pkh prefix
	DIDPKHPrefix       = "did:pkh"
	pkhContextFilename = "did-pkh-context.json"
)

const (
	Bitcoin  Network = "Bitcoin"
	Ethereum Network = "Ethereum"
	Polygon  Network = "Polygon"
)

var didPKHNetworkPrefixMap = map[Network][]string{
	Bitcoin:  {"bip122:000000000019d6689c085ae165831e93", "EcdsaSecp256k1RecoveryMethod2020"},
	Ethereum: {"eip155:1", "EcdsaSecp256k1RecoveryMethod2020"},
	Polygon:  {"eip155:137", "EcdsaSecp256k1RecoveryMethod2020"},
}

// The following context should be manually inserted into each DID Document. This will likely change
// over time as new verification methods are supported, and general-purpose methods are specified.
var knownDIDPKHContext, _ = schema.GetKnownSchema(pkhContextFilename)

// CreateDIDPKHFromNetwork constructs a did:pkh from a network and the networks native address.
func CreateDIDPKHFromNetwork(network Network, address string) (*DIDPKH, error) {
	if _, ok := didPKHNetworkPrefixMap[network]; ok {
		split := strings.Split(didPKHNetworkPrefixMap[network][0], ":")
		return CreateDIDPKH(split[0], split[1], address)
	}

	return nil, util.LoggingNewError(fmt.Sprintf("unsupported network: %s", string(network)))
}

// CreateDIDPKH constructs a did:pkh from a namespace, reference, and account address.
// Reference: did:pkh:namespace:reference:account_address
func CreateDIDPKH(namespace, reference, address string) (*DIDPKH, error) {
	did := DIDPKH(fmt.Sprintf("%s:%s:%s:%s", DIDPKHPrefix, namespace, reference, address))

	if !IsValidPKH(did) {
		return nil, util.LoggingNewError(fmt.Sprintf("Pkh DID is not valid: %s", string(did)))
	}

	return &did, nil
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
	for network, prefix := range didPKHNetworkPrefixMap {
		if strings.Contains(string(didpkh), prefix[0]+":") {
			return &network, nil
		}
	}

	return nil, util.LoggingNewError("network not supported")
}

// Expand turns the DID key into a complaint DID Document
func (did DIDPKH) Expand() (*DIDDocument, error) {
	verificationMethod, err := constructPKHVerificationMethod(did)

	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not construct verification method")
	}

	var knownDIDPKHContextJSON interface{}
	if err := json.Unmarshal([]byte(knownDIDPKHContext), &knownDIDPKHContextJSON); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not unmarshal known context json")
	}

	verificationMethodSet := []VerificationMethodSet{
		string(did) + "#blockchainAccountId",
	}

	return &DIDDocument{
		Context:              knownDIDPKHContextJSON,
		ID:                   string(did),
		VerificationMethod:   []VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
		CapabilityInvocation: verificationMethodSet,
	}, nil
}

func constructPKHVerificationMethod(did DIDPKH) (*VerificationMethod, error) {
	if !IsValidPKH(did) || did.Parse() == "" {
		return nil, util.LoggingNewError("Pkh DID is not valid")
	}

	network, err := GetNetwork(did)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not find network")
	}
	verificationType := didPKHNetworkPrefixMap[*network][1]

	return &VerificationMethod{
		ID:                  string(did) + "#blockchainAccountId",
		Type:                cryptosuite.LDKeyType(verificationType),
		Controller:          string(did),
		BlockchainAccountID: did.Parse(),
	}, nil
}

// IsValidPKH checks if a pkh did is valid based on the following parameters:

// pkh-did    = "did:pkh:" address
// address    = account_id according to [CAIP-10]

// account_id:        chain_id + ":" + account_address
// chain_id:          [-a-z0-9]{3,8}:[-a-zA-Z0-9]{1,32}
// account_address:   [a-zA-Z0-9]{1,64}

// chain_id:    namespace + ":" + reference
// namespace:   [-a-z0-9]{3,8}
// reference:   [-a-zA-Z0-9]{1,32}
func IsValidPKH(did DIDPKH) bool {
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

func GetSupportedNetworks() []Network {
	var networks []Network

	for network := range didPKHNetworkPrefixMap {
		networks = append(networks, network)
	}

	return networks
}
