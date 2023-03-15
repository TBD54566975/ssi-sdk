package util

import (
	"net/url"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// URL is a wrapper struct of url.URL in order to unmarshal(marshal) URLs from(to) strings.
type URL struct {
	url.URL
}

func (u URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.URL.String())
}

func (u *URL) UnmarshalJSON(data []byte) error {
	var dataStr string

	if err := json.Unmarshal(data, &dataStr); err != nil {
		return errors.Wrap(err, "unmarshalling")
	}
	parsed, err := url.Parse(dataStr)
	if err != nil {
		return errors.Wrap(err, "parsing url")
	}
	u.URL = *parsed
	return nil
}
