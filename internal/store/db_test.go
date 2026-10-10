package store

import (
	"strings"
	"testing"
)

func TestRebind(t *testing.T) {
	// SQLite: placeholders untouched.
	if got := rebind(false, "a=? AND b=?"); got != "a=? AND b=?" {
		t.Fatalf("sqlite rebind changed query: %q", got)
	}
	// Postgres: ? -> $1,$2,... in order.
	if got := rebind(true, "a=? AND b=? OR c=?"); got != "a=$1 AND b=$2 OR c=$3" {
		t.Fatalf("pg rebind = %q", got)
	}
	if got := rebind(true, "no placeholders"); got != "no placeholders" {
		t.Fatalf("pg rebind of literal = %q", got)
	}
}

// TestDDLPostgresTypes guards the dialect type mapping — in particular that
// SQLite's 64-bit INTEGER becomes Postgres BIGINT, not int4 (the overflow bug
// that broke the first prod migration on a 32GB host).
func TestDDLPostgresTypes(t *testing.T) {
	pg := &DB{pg: true}
	out := pg.ddl("CREATE TABLE t (id INTEGER PRIMARY KEY, mem INTEGER NOT NULL, blob BLOB)")

	if !strings.Contains(out, "BIGSERIAL PRIMARY KEY") {
		t.Errorf("INTEGER PRIMARY KEY should map to BIGSERIAL: %s", out)
	}
	if !strings.Contains(out, "mem BIGINT") {
		t.Errorf("standalone INTEGER should map to BIGINT (int4 overflows): %s", out)
	}
	if strings.Contains(out, "INTEGER") {
		t.Errorf("no INTEGER (int4) should remain in PG DDL: %s", out)
	}
	if !strings.Contains(out, "BYTEA") || strings.Contains(out, "BLOB") {
		t.Errorf("BLOB should map to BYTEA: %s", out)
	}

	// SQLite dialect leaves DDL untouched.
	sqlite := &DB{pg: false}
	in := "CREATE TABLE t (id INTEGER PRIMARY KEY, blob BLOB)"
	if got := sqlite.ddl(in); got != in {
		t.Errorf("sqlite ddl should be identity: %q", got)
	}
}
