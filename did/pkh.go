package did

import (
	"embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

type (
	DIDPKH  string
	Network string
)

var (
	//go:embed context
	knownContexts embed.FS
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

const (
	BitcoinNetworkPrefix  = "bip122:000000000019d6689c085ae165831e93"
	EthereumNetworkPrefix = "eip155:1"
	PolygonNetworkPrefix  = "eip155:137"

	EcdsaSecp256k1RecoveryMethod2020 = "EcdsaSecp256k1RecoveryMethod2020"
)

// GetDIDPKHContext returns a context which should be manually inserted into each did:pkh document. This will likely
// change over time as new verification methods are supported, and general-purpose methods are specified.
func GetDIDPKHContext() (string, error) {
	b, err := knownContexts.ReadFile("context/" + pkhContextFilename)
	return string(b), err
}

// CreateDIDPKHFromNetwork constructs a did:pkh from a network and the networks native address.
func CreateDIDPKHFromNetwork(network Network, address string) (*DIDPKH, error) {
	prefix, err := GetDIDPKHPrefixForNetwork(network)
	if err != nil {
		return nil, err
	}
	split := strings.Split(prefix, ":")
	return CreateDIDPKH(split[0], split[1], address)
}

// CreateDIDPKH constructs a did:pkh from a namespace, reference, and account address.
// Reference: did:pkh:namespace:reference:account_address
func CreateDIDPKH(namespace, reference, address string) (*DIDPKH, error) {
	did := DIDPKH(fmt.Sprintf("%s:%s:%s:%s", DIDPKHPrefix, namespace, reference, address))

	if !IsValidPKH(did) {
		return nil, util.LoggingNewError(fmt.Sprintf("PKH DID is not valid: %s", string(did)))
	}

	return &did, nil
}

func (d DIDPKH) IsValid() bool {
	return IsValidPKH(d)
}

func (d DIDPKH) String() string {
	return string(d)
}

// Suffix Parse returns the value without the `did:pkh` prefix
func (d DIDPKH) Suffix() (string, error) {
	split := strings.Split(string(d), DIDPKHPrefix+":")
	if len(split) != 2 {
		return "", errors.New("invalid did pkh")
	}
	return split[1], nil
}

func (d DIDPKH) Method() Method {
	return PKHMethod
}

// GetDIDPKHPrefixForNetwork returns the did:pkh prefix for a given network
func GetDIDPKHPrefixForNetwork(n Network) (string, error) {
	switch n {
	case Bitcoin:
		return BitcoinNetworkPrefix, nil
	case Ethereum:
		return EthereumNetworkPrefix, nil
	case Polygon:
		return PolygonNetworkPrefix, nil
	}
	return "", fmt.Errorf("unsupported did:pkh network: %s", n)
}

// GetDIDPKHNetworkForPrefix returns the did:pkh network for a given prefix
func GetDIDPKHNetworkForPrefix(p string) (Network, error) {
	switch p {
	case BitcoinNetworkPrefix:
		return Bitcoin, nil
	case EthereumNetworkPrefix:
		return Ethereum, nil
	case PolygonNetworkPrefix:
		return Polygon, nil
	}
	return "", fmt.Errorf("unsupported did:pkh prefix: %s", p)
}

// GetDIDPKHNetworkForDID returns the network for a given did:pkh
func GetDIDPKHNetworkForDID(did string) (Network, error) {
	prefixes := GetDIDPKHNetworkPrefixes()
	for _, prefix := range prefixes {
		if strings.Contains(did, prefix+":") {
			return GetDIDPKHNetworkForPrefix(prefix)
		}
	}
	return "", fmt.Errorf("could not find network for did:pkh DID: %s", did)
}

// GetVerificationTypeForNetwork returns the verification key type for a given network
func GetVerificationTypeForNetwork(n Network) (string, error) {
	switch n {
	case Bitcoin, Ethereum, Polygon:
		return EcdsaSecp256k1RecoveryMethod2020, nil
	}
	return "", fmt.Errorf("unsupported did:pkh network: %s", n)
}

func GetSupportedPKHNetworks() []Network {
	return []Network{Bitcoin, Ethereum, Polygon}
}

func GetDIDPKHNetworkPrefixes() []string {
	return []string{BitcoinNetworkPrefix, EthereumNetworkPrefix, PolygonNetworkPrefix}
}

// Expand turns the DID key into a complaint DID Document
func (d DIDPKH) Expand() (*DIDDocument, error) {
	verificationMethod, err := constructPKHVerificationMethod(d)

	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not construct verification method")
	}

	knownDIDPKHContextJSON, err := GetDIDPKHContext()
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not get known context json")
	}

	contextJSON, err := util.ToJSONInterface(knownDIDPKHContextJSON)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not convert known context to json")
	}

	verificationMethodSet := []VerificationMethodSet{
		string(d) + "#blockchainAccountId",
	}

	return &DIDDocument{
		Context:              contextJSON,
		ID:                   string(d),
		VerificationMethod:   []VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
		CapabilityInvocation: verificationMethodSet,
	}, nil
}

func constructPKHVerificationMethod(did DIDPKH) (*VerificationMethod, error) {
	if !IsValidPKH(did) {
		parsed, err := did.Suffix()
		if err != nil || parsed == "" {
			return nil, util.LoggingNewError("PKH DID is not valid")
		}
	}

	network, err := GetDIDPKHNetworkForDID(did.String())
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not find network")
	}
	verificationType, err := GetVerificationTypeForNetwork(network)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not find verification type")
	}

	suffix, err := did.Suffix()
	if err != nil {
		return nil, err
	}
	return &VerificationMethod{
		ID:                  string(did) + "#blockchainAccountId",
		Type:                cryptosuite.LDKeyType(verificationType),
		Controller:          string(did),
		BlockchainAccountID: suffix,
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

type PKHResolver struct{}

func (r PKHResolver) Resolve(did string, opts ResolutionOptions) (*DIDResolutionResult, error) {
	if !strings.HasPrefix(did, DIDPKHPrefix) {
		return nil, fmt.Errorf("not a did:pkh DID: %s", did)
	}
	didPKH := DIDPKH(did)
	doc, err := didPKH.Expand()
	if err != nil {
		return nil, errors.Wrapf(err, "could not expand did:pkh DID: %s", did)
	}
	// TODO(gabe) full resolution support to be added in https://github.com/TBD54566975/ssi-sdk/issues/38
	return &DIDResolutionResult{DIDDocument: *doc}, nil
}

func (r PKHResolver) Method() Method {
	return PKHMethod
}
