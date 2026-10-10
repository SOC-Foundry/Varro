package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// orgs and users are the only foreign-key parents in the schema, so loading
// them first lets every other table's rows insert without disabling FK checks
// (which would need superuser).
var fkParents = []string{"orgs", "users"}

// MigrateData copies every row from a SQLite database file into a Postgres
// instance, for a one-time SQLite->Postgres cutover. The destination schema is
// created if absent; it must otherwise be EMPTY (this appends, it does not
// reconcile). It returns per-table source/destination row counts so the caller
// can verify the copy. Serial id sequences are reset afterward so new inserts
// don't collide with migrated ids.
func MigrateData(srcPath, dstDSN string, logf func(string)) (map[string][2]int, error) {
	if logf == nil {
		logf = func(string) {}
	}
	// Ensure the destination schema exists (CREATE TABLE IF NOT EXISTS + migrations).
	if st, err := Open(dstDSN); err != nil {
		return nil, fmt.Errorf("open/create destination schema: %w", err)
	} else {
		st.Close()
	}

	src, err := sql.Open("sqlite", srcPath)
	if err != nil {
		return nil, fmt.Errorf("open source: %w", err)
	}
	defer src.Close()
	src.SetMaxOpenConns(1)
	dst, err := sql.Open("pgx", dstDSN)
	if err != nil {
		return nil, fmt.Errorf("open destination: %w", err)
	}
	defer dst.Close()

	tables, err := sqliteTables(src)
	if err != nil {
		return nil, err
	}
	// Clear the destination first: creating the schema seeds the default org,
	// and emptying up front makes a re-run (e.g. dry-run then real cutover)
	// safe. CASCADE + RESTART IDENTITY handles FK order and resets sequences.
	for _, t := range tables {
		if _, err := dst.Exec(`TRUNCATE "` + t + `" RESTART IDENTITY CASCADE`); err != nil {
			return nil, fmt.Errorf("truncate %s: %w", t, err)
		}
	}
	// Order: FK parents first, then the rest.
	ordered := append([]string{}, fkParents...)
	for _, t := range tables {
		if t != "orgs" && t != "users" {
			ordered = append(ordered, t)
		}
	}

	counts := map[string][2]int{}
	for _, table := range ordered {
		if !contains(tables, table) {
			continue
		}
		n, err := copyTable(src, dst, table, logf)
		if err != nil {
			return counts, fmt.Errorf("copy %s: %w", table, err)
		}
		var dstN int
		dst.QueryRow(`SELECT count(*) FROM "` + table + `"`).Scan(&dstN)
		counts[table] = [2]int{n, dstN}
		logf(fmt.Sprintf("  %-16s src=%d dst=%d", table, n, dstN))
		if err := resetSequence(dst, table); err != nil {
			logf(fmt.Sprintf("  (seq reset skipped for %s: %v)", table, err))
		}
	}
	return counts, nil
}

func sqliteTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// copyTable streams every row of one table from src to dst in batches.
func copyTable(src, dst *sql.DB, table string, logf func(string)) (int, error) {
	rows, err := src.Query(`SELECT * FROM "` + table + `"`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = `"` + c + `"`
	}
	colList := strings.Join(quoted, ",")

	const batchRows = 500
	var batch []any
	pending := 0
	total := 0

	flush := func() error {
		if pending == 0 {
			return nil
		}
		var vb strings.Builder
		arg := 1
		for r := 0; r < pending; r++ {
			if r > 0 {
				vb.WriteByte(',')
			}
			vb.WriteByte('(')
			for c := 0; c < len(cols); c++ {
				if c > 0 {
					vb.WriteByte(',')
				}
				fmt.Fprintf(&vb, "$%d", arg)
				arg++
			}
			vb.WriteByte(')')
		}
		q := fmt.Sprintf(`INSERT INTO "%s" (%s) VALUES %s`, table, colList, vb.String())
		if _, err := dst.Exec(q, batch...); err != nil {
			return err
		}
		batch = batch[:0]
		pending = 0
		return nil
	}

	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return total, err
		}
		batch = append(batch, vals...)
		pending++
		total++
		if pending >= batchRows {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return total, err
	}
	if err := flush(); err != nil {
		return total, err
	}
	return total, nil
}

// resetSequence advances a table's serial "id" sequence past the max migrated
// id. A no-op (nil) for tables without a serial id.
func resetSequence(dst *sql.DB, table string) error {
	var seq sql.NullString
	if err := dst.QueryRow(`SELECT pg_get_serial_sequence($1, 'id')`, table).Scan(&seq); err != nil {
		return nil // no "id" column
	}
	if !seq.Valid || seq.String == "" {
		return nil
	}
	_, err := dst.Exec(
		fmt.Sprintf(`SELECT setval('%s', (SELECT COALESCE(MAX(id),1) FROM "%s"))`, seq.String, table))
	return err
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
