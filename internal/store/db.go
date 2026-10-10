package store

import (
	"context"
	"database/sql"
	"strings"
)

// DB wraps *sql.DB with dialect awareness so the rest of the store can write
// one set of queries (SQLite "?" placeholders) and run them on either SQLite
// or Postgres. For Postgres, "?" placeholders are rebound to "$1,$2,…".
type DB struct {
	sdb *sql.DB
	pg  bool
}

// Tx is the transaction counterpart of DB with the same rebinding.
type Tx struct {
	stx *sql.Tx
	pg  bool
}

// rebind converts "?" placeholders to "$1,$2,…" for Postgres. Queries contain
// no literal "?" outside placeholders, so a straight scan is safe.
func rebind(pg bool, q string) string {
	if !pg {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 8)
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// greatest returns the max-of-two SQL expression for the active dialect:
// SQLite's scalar MAX(a,b) vs Postgres's GREATEST(a,b).
func (d *DB) greatest(a, b string) string {
	if d.pg {
		return "GREATEST(" + a + ", " + b + ")"
	}
	return "MAX(" + a + ", " + b + ")"
}

func (d *DB) IsPostgres() bool { return d.pg }

func (d *DB) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return d.sdb.ExecContext(ctx, rebind(d.pg, q), args...)
}
func (d *DB) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return d.sdb.QueryContext(ctx, rebind(d.pg, q), args...)
}
func (d *DB) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return d.sdb.QueryRowContext(ctx, rebind(d.pg, q), args...)
}
func (d *DB) Exec(q string, args ...any) (sql.Result, error) {
	return d.sdb.Exec(rebind(d.pg, q), args...)
}

// insertReturningID runs an INSERT and returns the generated id. Postgres has
// no LastInsertId, so it uses RETURNING id; SQLite uses LastInsertId.
func (d *DB) insertReturningID(ctx context.Context, query string, args ...any) (int64, error) {
	if d.pg {
		var id int64
		err := d.QueryRowContext(ctx, query+" RETURNING id", args...).Scan(&id)
		return id, err
	}
	res, err := d.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// forPostgres adapts the SQLite-authored schema DDL for Postgres: autoincrement
// integer primary keys become BIGSERIAL and BLOB becomes BYTEA.
func (d *DB) ddl(schema string) string {
	if !d.pg {
		return schema
	}
	// SQLite INTEGER is 64-bit, so the faithful Postgres type is BIGINT, not
	// INTEGER (int4) — values like mem_total overflow int4. Autoincrement PKs
	// become BIGSERIAL. Order matters: handle the PK form before the generic
	// INTEGER->BIGINT pass.
	schema = strings.ReplaceAll(schema, "INTEGER PRIMARY KEY", "BIGSERIAL PRIMARY KEY")
	schema = strings.ReplaceAll(schema, "INTEGER", "BIGINT")
	schema = strings.ReplaceAll(schema, "BLOB", "BYTEA")
	return schema
}

func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, err := d.sdb.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Tx{stx: tx, pg: d.pg}, nil
}
func (d *DB) Close() error { return d.sdb.Close() }

func (t *Tx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return t.stx.ExecContext(ctx, rebind(t.pg, q), args...)
}
func (t *Tx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return t.stx.QueryContext(ctx, rebind(t.pg, q), args...)
}
func (t *Tx) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	// The statement is rebound at prepare time, so later Exec/Query on it need
	// no further rewriting.
	return t.stx.PrepareContext(ctx, rebind(t.pg, q))
}
func (t *Tx) Commit() error   { return t.stx.Commit() }
func (t *Tx) Rollback() error { return t.stx.Rollback() }
