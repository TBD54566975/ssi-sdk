package did

import (
	"embed"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/goccy/go-json"
)

const (
	testDataDirectory = "testdata"
)

var (
	//go:embed testdata
	testVectorPKHDIDFS embed.FS
)

var pkhTestVectors = map[Network][]string{
	Bitcoin:  {BitcoinNetworkPrefix, "did-pkh-bitcoin-doc.json"},
	Ethereum: {EthereumNetworkPrefix, "did-pkh-ethereum-doc.json"},
	Polygon:  {PolygonNetworkPrefix, "did-pkh-polygon-doc.json"},
}

func TestDIDPKHVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for network, tv := range pkhTestVectors {
		gotTestVector, err := testVectorPKHDIDFS.ReadFile(testDataDirectory + "/" + tv[1])
		assert.NoError(t, err)

		// Test Known DIDPKH
		var knownDIDPKH Document
		err = json.Unmarshal([]byte(gotTestVector), &knownDIDPKH)

		assert.NoError(t, err)
		assert.NoError(t, knownDIDPKH.IsValid())
		assert.False(t, knownDIDPKH.IsEmpty())

		knownDIDBytes, err := json.Marshal(knownDIDPKH)
		assert.NoError(t, err)
		assert.JSONEqf(t, string(gotTestVector), string(knownDIDBytes), "Known DID Serializtion Error")

		// Test Create DIDPKH With same ID as KnownDIDPKH
		split := strings.Split(knownDIDPKH.ID, ":")
		address := split[len(split)-1]
		testDIDPKH, err := CreateDIDPKHFromNetwork(network, address)
		assert.NoError(t, err)
		assert.NotEmpty(t, testDIDPKH)

		testDIDPKHDoc, err := testDIDPKH.Expand()

		assert.NoError(t, err)
		assert.NotEmpty(t, testDIDPKHDoc)
		assert.Equal(t, string(*testDIDPKH), testDIDPKHDoc.ID)

		// Compare Known and Testing DIDPKH Document. This compares the known PKH DID Document with the one we generate
		generatedDIDBytes, err := json.Marshal(testDIDPKHDoc)
		assert.NoError(t, err)
		assert.JSONEqf(t, string(generatedDIDBytes), string(knownDIDBytes), "Generated DIDPKH does not match known DIDPKH")
	}
}

func TestParse(t *testing.T) {
	// happy path
	address := "0xb9c5714089478a327f09197987f16f9e5d936e8a"
	didPKH, err := CreateDIDPKHFromNetwork(Ethereum, address)
	assert.NoError(t, err)
	assert.True(t, IsValidPKH(*didPKH))
	parsed, err := didPKH.Suffix()
	assert.NoError(t, err)
	assert.NotContains(t, parsed, DIDPKHPrefix)

	// unhappy path
	badParsed, err := DIDPKH("bad").Suffix()
	assert.Error(t, err)
	assert.Equal(t, badParsed, "")
}

func TestCreateDIDPKH(t *testing.T) {
	t.Run("Test ETH Happy Path From Network", func(tt *testing.T) {
		address := "0xb9c5714089478a327f09197987f16f9e5d936e8a"
		didPKH, err := CreateDIDPKHFromNetwork(Ethereum, address)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, didPKH)
		assert.Equal(tt, string(*didPKH), "did:pkh:eip155:1:"+address)

		didDoc, err := didPKH.Expand()

		assert.NoError(tt, err)
		assert.NotEmpty(tt, didDoc)
		assert.Equal(tt, string(*didPKH), didDoc.ID)

		generatedDIDDocBytes, err := json.Marshal(didDoc)
		assert.NoError(tt, err)

		testVectorDIDDoc, err := testVectorPKHDIDFS.ReadFile(testDataDirectory + "/" + pkhTestVectors[Ethereum][1])
		assert.NoError(tt, err)

		var expandedTestDIDDoc Document
		err = json.Unmarshal([]byte(testVectorDIDDoc), &expandedTestDIDDoc)
		assert.NoError(tt, err)
		expandedTestDIDDocBytes, err := json.Marshal(expandedTestDIDDoc)
		assert.NoError(tt, err)

		assert.Equal(tt, string(generatedDIDDocBytes), string(expandedTestDIDDocBytes))
	})

	t.Run("Test Unhappy Path", func(tt *testing.T) {
		_, err := CreateDIDPKHFromNetwork("bad", "bad")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported did:pkh network: bad")
	})
}

func TestIsValidPKH(t *testing.T) {
	// Bitcoin
	assert.True(t, IsValidPKH("did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6"))
	// Dogecoin
	assert.True(t, IsValidPKH("did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"))
	// Ethereum
	assert.True(t, IsValidPKH("did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
	// Solana
	assert.True(t, IsValidPKH("did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev"))

	// Invalid DIDs
	assert.False(t, IsValidPKH(""))
	assert.False(t, IsValidPKH("notpkh"))
	assert.False(t, IsValidPKH("alsonot:valid:pkh"))
	assert.False(t, IsValidPKH("did:pkh::"))
	assert.False(t, IsValidPKH("did:pkh:eip155:1:"))
	assert.False(t, IsValidPKH("did:pkh:eip155::0xb9c5714089478a327f09197987f16f9e5d936e8a"))
	assert.False(t, IsValidPKH("did:pkh:NOCAP:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
}

func TestGetNetwork(t *testing.T) {
	t.Run("Test Known Networks", func(tt *testing.T) {
		for network := range pkhTestVectors {
			didPKH, err := CreateDIDPKHFromNetwork(network, "dummyaddress")
			assert.NoError(t, err)

			n, err := GetDIDPKHNetworkForDID(didPKH.String())
			assert.NoError(tt, err)

			assert.Equal(tt, network, n)
		}
	})

	// test bad network
	t.Run("Test Unknown Network", func(tt *testing.T) {
		_, err := CreateDIDPKHFromNetwork("bad", "dummyaddress")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported did:pkh network: bad")
	})
}

func TestGetSupportedNetworks(t *testing.T) {
	supportedNetworks := GetSupportedPKHNetworks()

	supportedNetworksSet := make(map[Network]bool)
	for i := range supportedNetworks {
		supportedNetworksSet[supportedNetworks[i]] = true
	}

	for network := range pkhTestVectors {
		assert.True(t, supportedNetworksSet[network])
	}
}
