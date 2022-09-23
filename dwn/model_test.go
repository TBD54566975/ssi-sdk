package dwn

import (
	"embed"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/goccy/go-json"
)

const (
	TestVector1 string = "dwn-message-example-1.json"
)

var (
	//go:embed testdata
	testVectorFS embed.FS
	testVectors  = []string{TestVector1}
)

func TestDwnMessage(t *testing.T) {

	t.Run("DWN Message Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(testVectors[0])
		assert.NoError(tt, err)

		var msg DWNMessage
		err = json.Unmarshal([]byte(vector), &msg)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, msg)

		assert.NoError(tt, msg.IsValid())

		roundTripBytes, err := json.Marshal(msg)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Empty DWN Message", func(tt *testing.T) {
		msg := DWNMessage{}

		assert.Error(tt, msg.IsValid())
		assert.True(tt, msg.IsEmpty())
	})
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectorFS.ReadFile("testdata/" + fileName)
	return string(b), err
}
