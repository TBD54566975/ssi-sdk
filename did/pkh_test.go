package did

import (
	"embed"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"

	"github.com/goccy/go-json"
)

const (
	testDataDirectory = "testdata"
)

var (
	//go:embed testdata
	testVectorPKHDIDFS embed.FS
)

var PKHTestVectors = map[Network][]string{
	Bitcoin:  {"bip122:000000000019d6689c085ae165831e93", "did-pkh-bitcoin-doc.json"},
	Ethereum: {"eip155:1", "did-pkh-ethereum-doc.json"},
	Polygon:  {"eip155:137", "did-pkh-polygon-doc.json"},
}

func TestDIDPKHVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for network, tv := range PKHTestVectors {
		gotTestVector, err := testVectorPKHDIDFS.ReadFile(testDataDirectory + "/" + tv[1])
		assert.NoError(t, err)

		// Test Known DIDPKH
		var knownDIDPKH DIDDocument
		err = json.Unmarshal([]byte(gotTestVector), &knownDIDPKH)

		assert.NoError(t, err)
		assert.NoError(t, knownDIDPKH.IsValid())
		assert.False(t, knownDIDPKH.IsEmpty())

		knownDIDBytes, err := json.Marshal(knownDIDPKH)
		assert.NoError(t, err)
		assert.JSONEqf(t, string(gotTestVector), string(knownDIDBytes), "Known DID Serializtion error")

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

func TestCreateDIDPKH(t *testing.T) {
	address := "0xb9c5714089478a327f09197987f16f9e5d936e8a"
	didPKH, err := CreateDIDPKHFromNetwork(Ethereum, address)
	assert.NoError(t, err)
	assert.NotEmpty(t, didPKH)
	assert.Equal(t, string(*didPKH), "did:pkh:eip155:1:"+address)

	didDoc, err := didPKH.Expand()

	assert.NoError(t, err)
	assert.NotEmpty(t, didDoc)
	assert.Equal(t, string(*didPKH), didDoc.ID)

	generatedDIDDocBytes, err := json.Marshal(didDoc)
	assert.NoError(t, err)

	testVectorDIDDoc, err := testVectorPKHDIDFS.ReadFile(testDataDirectory + "/" + PKHTestVectors[Ethereum][1])
	assert.NoError(t, err)

	var expandedTestDIDDoc DIDDocument
	json.Unmarshal([]byte(testVectorDIDDoc), &expandedTestDIDDoc)
	expandedTestDIDDocBytes, err := json.Marshal(expandedTestDIDDoc)
	assert.NoError(t, err)

	assert.Equal(t, string(generatedDIDDocBytes), string(expandedTestDIDDocBytes))
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
	assert.False(t, IsValidPKH("did:pkh::"))
	assert.False(t, IsValidPKH("did:pkh:eip155:1:"))
	assert.False(t, IsValidPKH("did:pkh:NOCAP:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
}

func TestGetNetwork(t *testing.T) {
	for network := range PKHTestVectors {
		didPKH, err := CreateDIDPKHFromNetwork(network, "dummyaddress")
		assert.NoError(t, err)

		ntwrk, err := GetNetwork(*didPKH)
		assert.NoError(t, err)

		assert.Equal(t, network, *ntwrk)
	}
}

func TestGetSupportedNetworks(t *testing.T) {
	supportedNetworks := GetSupportedNetworks()

	supportedNetworksSet := make(map[Network]bool)
	for i := range supportedNetworks {
		supportedNetworksSet[supportedNetworks[i]] = true
	}

	for network := range PKHTestVectors {
		assert.True(t, supportedNetworksSet[network])
	}
}
