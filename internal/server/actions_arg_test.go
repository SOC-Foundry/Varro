package server

import (
	"testing"

	"github.com/soc-foundry/varro/internal/model"
)

func TestValidateActionArg(t *testing.T) {
	ok := func(typ, arg string) {
		t.Helper()
		if err := validateActionArg(typ, arg); err != nil {
			t.Errorf("validateActionArg(%q,%q) = %v, want nil", typ, arg, err)
		}
	}
	bad := func(typ, arg string) {
		t.Helper()
		if err := validateActionArg(typ, arg); err == nil {
			t.Errorf("validateActionArg(%q,%q) = nil, want error", typ, arg)
		}
	}
	ok(model.ActionKillProcess, "42")
	bad(model.ActionKillProcess, "1")   // never init/kernel
	bad(model.ActionKillProcess, "abc") // non-numeric
	ok(model.ActionBlockIP, "203.0.113.5")
	ok(model.ActionBlockIP, "2001:db8::1")
	bad(model.ActionBlockIP, "not-an-ip")
	ok(model.ActionUnblockIP, "203.0.113.5")
	ok(model.ActionQuarantineFile, "/tmp/evil")
	bad(model.ActionQuarantineFile, "   ")
	ok(model.ActionIsolate, "") // no arg required
}
