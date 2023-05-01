package jwx

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed testdata
	testData embed.FS
)

const (
	dilithiumPublicJWK  string = "jwk-dilithium-vector-public.json"
	dilithiumPrivateJWK string = "jwk-dilithium-vector-private.json"
	dilithiumJWS        string = "jws-dilithium-vector.json"
)

func getTestData(fileName string) ([]byte, error) {
	return testData.ReadFile("testdata/" + fileName)
}

// retrieveTestVectorAs retrieves a test vector from the testdata folder and unmarshals it into the given interface
func retrieveTestVectorAs(t *testing.T, fileName string, output interface{}) {
	t.Helper()
	testDataBytes, err := getTestData(fileName)
	require.NoError(t, err)
	err = json.Unmarshal(testDataBytes, output)
	require.NoError(t, err)
}
