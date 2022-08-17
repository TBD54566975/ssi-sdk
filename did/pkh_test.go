package did

import (
	"embed"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"

	"github.com/goccy/go-json"
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
		gotTestVector, err := testVectorPKHDIDFS.ReadFile("testdata/" + tv[1])
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
		generatedDIDBytes, _ := json.Marshal(testDIDPKHDoc)
		assert.JSONEqf(t, string(generatedDIDBytes), string(knownDIDBytes), "Generated DIDPKH does not match known DIDPKH")
	}
}

func TestCreateDIDPKH(t *testing.T) {
	address := "0xb9c5714089478a327f09197987f16f9e5d936e8a"
	didPKH, err := CreateDIDPKHFromNetwork(Ethereum, address)
	assert.NoError(t, err)
	assert.NotEmpty(t, didPKH)

	didDoc, err := didPKH.Expand()

	assert.NoError(t, err)
	assert.NotEmpty(t, didDoc)
	assert.Equal(t, string(*didPKH), didDoc.ID)

	generatedDidDoc, _ := json.Marshal(didDoc)
	fmt.Println(string(generatedDidDoc))

	testVectorDidDoc, _ := testVectorPKHDIDFS.ReadFile("testdata/" + PKHTestVectors[Ethereum][1])

	var expandedTestDidDoc DIDDocument
	json.Unmarshal([]byte(testVectorDidDoc), &expandedTestDidDoc)

	expandedTestDidDocString, _ := json.Marshal(expandedTestDidDoc)
	fmt.Println(string(expandedTestDidDocString))

	assert.Equal(t, generatedDidDoc, expandedTestDidDocString)
}

func TestIsValidPKH(t *testing.T) {
	// Bitcoin
	assert.True(t, isValidPKH("did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6"))
	// Dogecoin
	assert.True(t, isValidPKH("did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"))
	// Ethereum
	assert.True(t, isValidPKH("did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
	// Solana
	assert.True(t, isValidPKH("did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev"))

	// Invalid DIDs
	assert.False(t, isValidPKH(""))
	assert.False(t, isValidPKH("did:pkh::"))
	assert.False(t, isValidPKH("did:pkh:eip155:1:"))
	assert.False(t, isValidPKH("did:pkh:NOCAP:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
}

func TestGetNetwork(t *testing.T) {
	for network, _ := range PKHTestVectors {
		didPKH, _ := CreateDIDPKHFromNetwork(network, "dummyaddress")
		ntwrk, _ := GetNetwork(*didPKH)
		assert.Equal(t, network, *ntwrk)
	}
}
