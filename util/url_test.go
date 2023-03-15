package util

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURL_MarshalJSON(t *testing.T) {
	u := URL{url.URL{Scheme: "https", Host: "example.com"}}

	got, err := u.MarshalJSON()

	expected := []byte(`"https://example.com"`)
	assert.NoError(t, err)
	assert.Equal(t, expected, got)
}

func TestURL_UnmarshalJSON(t *testing.T) {
	data := []byte(`"web5://tbd.website"`)
	var u URL

	assert.NoError(t, u.UnmarshalJSON(data))

	expected := URL{url.URL{Scheme: "web5", Host: "tbd.website"}}
	assert.Equal(t, expected, u)
}
