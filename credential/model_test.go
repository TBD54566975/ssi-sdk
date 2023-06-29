package credential

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"

	"github.com/stretchr/testify/assert"
)

// These test vectors are taken from the vc-data-model spec example
// e.g. https://www.w3.org/TR/vc-data-model/#example-a-simple-example-of-a-verifiable-credential
const (
	VCTestVector1 string = "vc-example-1.json"
	VCTestVector2 string = "vc-example-11.json"
	VCTestVector3 string = "vc-example-20.json"
	VCTestVector4 string = "vc-example-21.json"
	VPTestVector1 string = "vp-example-2.json"
	VPTestVector2 string = "vp-example-22.json"
)

var (
	//go:embed testdata
	testVectors   embed.FS
	vcTestVectors = []string{VCTestVector1, VCTestVector2, VCTestVector3, VCTestVector4}
	vpTestVectors = []string{VPTestVector1, VPTestVector2}
)

func TestVCVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for _, tv := range vcTestVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		var vc VerifiableCredential
		err = json.Unmarshal([]byte(gotTestVector), &vc)
		assert.NoError(t, err)

		assert.NoError(t, vc.IsValid())
		assert.False(t, vc.IsEmpty())

		vcBytes, err := json.Marshal(vc)
		assert.NoError(t, err)
		assert.JSONEq(t, gotTestVector, string(vcBytes))
	}
}

func TestVPVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for _, tv := range vpTestVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		var vp VerifiablePresentation
		err = json.Unmarshal([]byte(gotTestVector), &vp)
		assert.NoError(t, err)

		assert.NoError(t, vp.IsValid())
		assert.False(t, vp.IsEmpty())

		vpBytes, err := json.Marshal(vp)
		assert.NoError(t, err)
		assert.JSONEq(t, gotTestVector, string(vpBytes))
	}
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}

func TestVerifiableCredential_IssuerID(t *testing.T) {
	tests := []struct {
		name   string
		issuer any
		want   string
	}{
		{
			name:   "issuer as string",
			issuer: "hello",
			want:   "hello",
		},
		{
			name:   "issuer as string array",
			issuer: []string{"hello"},
			want:   "hello",
		},
		{
			name: "issuer as object with id",
			issuer: map[string]any{
				"id": "hello",
			},
			want: "hello",
		},
		{
			name: "issuer as anything else",
			issuer: struct{ ID string }{
				ID: "hello",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VerifiableCredential{
				Issuer: tt.issuer,
			}
			assert.Equalf(t, tt.want, v.IssuerID(), "IssuerID()")
		})
	}
}
