//go:build linux

package collect

import (
	"encoding/json"
	"testing"
)

func TestJSONString(t *testing.T) {
	cases := map[string]string{
		`"hello"`:          "hello",        // plain string
		`"with \"quote\""`: `with "quote"`, // escaped
		`[104,105]`:        "",             // byte array (non-UTF8 MESSAGE) → skipped
		`123`:              "",             // number → skipped
		`null`:             "",             // null → skipped
		``:                 "",             // absent field
	}
	for raw, want := range cases {
		got := jsonString(json.RawMessage(raw))
		if got != want {
			t.Errorf("jsonString(%q) = %q, want %q", raw, got, want)
		}
	}
}
