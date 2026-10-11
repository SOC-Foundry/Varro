package server

import "testing"

func TestCountryOf(t *testing.T) {
	cases := map[string]string{
		"US · AS15169 Google":  "US",
		"GB · AS16509 Amazon":  "GB",
		"US":                   "US",
		"US/AS15169":           "US",
		"":                     "",
		"AS15169 Google":       "", // ASN with no leading country
		"Unknown":              "", // not a 2-letter standalone token
		"DE · AS24940 Hetzner": "DE",
	}
	for geo, want := range cases {
		if got := countryOf(geo); got != want {
			t.Errorf("countryOf(%q) = %q, want %q", geo, got, want)
		}
	}
}
