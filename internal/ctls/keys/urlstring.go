package keys

import (
	"encoding/json"
	"net/url"
	"strings"
)

type URLString struct {
	// Key is a normalized URL that is used to help
	// with storage of a variety of control components.
	Key string
	// URL is the successfully parsed raw string.
	URL *url.URL
	// Raw is the unparsed response from the registry.
	Raw string
}

func NewURLString(rawURL string) URLString {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return URLString{}
	}

	return URLString{
		Raw: rawURL,
		Key: normalizeURL(parsed),
		URL: parsed,
	}
}

func (u *URLString) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}

	parsed, err := url.Parse(str)
	if err != nil {
		return err
	}

	u.Raw = str
	u.Key = normalizeURL(parsed)
	u.URL = parsed

	return err
}

func (u *URLString) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.Raw)
}

//

func normalizeURL(parsed *url.URL) string {
	hostname := parsed.Hostname()
	if hostname == "" {
		return parsed.String()
	}

	return strings.TrimPrefix(hostname, "www.")
}
