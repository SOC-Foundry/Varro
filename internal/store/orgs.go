package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

func randomID(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---- orgs ----

func (s *Store) CreateOrg(ctx context.Context, name string) (model.Org, error) {
	id, err := randomID(6)
	if err != nil {
		return model.Org{}, err
	}
	org := model.Org{ID: id, Name: name, CreatedAt: time.Now().UTC()}
	_, err = s.db.ExecContext(ctx, `INSERT INTO orgs (id, name, created_at) VALUES (?, ?, ?)`,
		org.ID, org.Name, org.CreatedAt.Unix())
	return org, err
}

func (s *Store) Orgs(ctx context.Context) ([]model.Org, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, auto_join_domain, created_at FROM orgs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Org
	for rows.Next() {
		var o model.Org
		var created int64
		if err := rows.Scan(&o.ID, &o.Name, &o.AutoJoinDomain, &created); err != nil {
			return nil, err
		}
		o.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, o)
	}
	return out, rows.Err()
}

// OrgByRef resolves an org by ID or (unique) name.
func (s *Store) OrgByRef(ctx context.Context, ref string) (model.Org, error) {
	var o model.Org
	var created int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, auto_join_domain, created_at FROM orgs WHERE id = ? OR name = ?`, ref, ref).
		Scan(&o.ID, &o.Name, &o.AutoJoinDomain, &created)
	if err == sql.ErrNoRows {
		return model.Org{}, fmt.Errorf("no org %q", ref)
	}
	if err != nil {
		return model.Org{}, err
	}
	o.CreatedAt = time.Unix(created, 0).UTC()
	return o, nil
}

// DeleteOrg removes an empty org (its tokens and memberships included).
// Orgs that still have endpoints are refused — decommission those first with
// DeleteEndpoint so history isn't silently orphaned.
func (s *Store) DeleteOrg(ctx context.Context, orgID string) error {
	if orgID == model.DefaultOrg {
		return fmt.Errorf("the default org cannot be deleted")
	}
	var endpoints int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM endpoints WHERE org_id = ?`, orgID).Scan(&endpoints); err != nil {
		return err
	}
	if endpoints > 0 {
		return fmt.Errorf("org still has %d endpoint(s); remove them first", endpoints)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		`DELETE FROM org_tokens WHERE org_id = ?`,
		`DELETE FROM org_members WHERE org_id = ?`,
		`DELETE FROM alerts WHERE org_id = ?`,
		`DELETE FROM events WHERE org_id = ?`,
		`DELETE FROM orgs WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, orgID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetOrgDomain sets (or clears) an org's auto-join email domain.
func (s *Store) SetOrgDomain(ctx context.Context, orgID, domain string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE orgs SET auto_join_domain = ? WHERE id = ?`, domain, orgID)
	return err
}

// OrgFIMPaths returns the org's file-integrity watchlist.
func (s *Store) OrgFIMPaths(ctx context.Context, orgID string) ([]string, error) {
	var raw string
	err := s.db.QueryRowContext(ctx,
		`SELECT fim_paths FROM orgs WHERE id = ?`, orgID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	if err := json.Unmarshal([]byte(raw), &paths); err != nil {
		return nil, nil // tolerate legacy/garbage values
	}
	return paths, nil
}

// SetOrgFIMPaths replaces the org's file-integrity watchlist.
func (s *Store) SetOrgFIMPaths(ctx context.Context, orgID string, paths []string) error {
	raw, err := json.Marshal(paths)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE orgs SET fim_paths = ? WHERE id = ?`, string(raw), orgID)
	return err
}

// OrgIDForDomain returns the org that auto-joins a given email domain, or "".
func (s *Store) OrgIDForDomain(ctx context.Context, domain string) (string, error) {
	if domain == "" {
		return "", nil
	}
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM orgs WHERE auto_join_domain = ?`, domain).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}

// ---- org enrollment tokens ----

// CreateOrgToken mints an enrollment token for an org, storing only its hash.
// The plaintext is returned exactly once.
func (s *Store) CreateOrgToken(ctx context.Context, orgID, name string, hash func(string) string) (string, error) {
	token, err := randomID(32)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO org_tokens (token_hash, org_id, name, created_at) VALUES (?, ?, ?, ?)`,
		hash(token), orgID, name, time.Now().Unix())
	return token, err
}

// OrgForTokenHash returns the org a hashed enrollment token belongs to, or "".
func (s *Store) OrgForTokenHash(ctx context.Context, tokenHash string) (string, error) {
	var orgID string
	err := s.db.QueryRowContext(ctx,
		`SELECT org_id FROM org_tokens WHERE token_hash = ?`, tokenHash).Scan(&orgID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return orgID, err
}

// ---- users ----

// UpsertGoogleUser creates or updates a user from a verified Google identity.
// The very first user of the instance becomes an admin.
func (s *Store) UpsertGoogleUser(ctx context.Context, sub, email, name string, forceAdmin bool) (model.User, error) {
	var u model.User
	var isAdmin int
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, is_admin FROM users WHERE google_sub = ? OR email = ?`, sub, email).
		Scan(&u.ID, &u.Email, &u.Name, &isAdmin)
	switch {
	case err == sql.ErrNoRows:
		var count int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
			return model.User{}, err
		}
		id, err := randomID(8)
		if err != nil {
			return model.User{}, err
		}
		admin := 0
		if count == 0 || forceAdmin {
			admin = 1
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO users (id, email, name, google_sub, is_admin, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			id, email, name, sub, admin, time.Now().Unix()); err != nil {
			return model.User{}, err
		}
		return model.User{ID: id, Email: email, Name: name, Admin: admin == 1}, nil
	case err != nil:
		return model.User{}, err
	}

	if forceAdmin && isAdmin == 0 {
		isAdmin = 1
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE users SET email = ?, name = ?, google_sub = ?, is_admin = ? WHERE id = ?`,
		email, name, sub, isAdmin, u.ID)
	if err != nil {
		return model.User{}, err
	}
	return model.User{ID: u.ID, Email: email, Name: name, Admin: isAdmin == 1}, nil
}

// ---- org membership ----

func (s *Store) AddOrgMember(ctx context.Context, orgID, email, role string) error {
	if role == "" {
		role = "member"
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO org_members (org_id, email, role) VALUES (?, ?, ?)
ON CONFLICT(org_id, email) DO UPDATE SET role=excluded.role`, orgID, email, role)
	return err
}

// OrgMembers lists an org's membership.
func (s *Store) OrgMembers(ctx context.Context, orgID string) ([]model.OrgMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT email, role FROM org_members WHERE org_id = ? ORDER BY email`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.OrgMember
	for rows.Next() {
		var m model.OrgMember
		if err := rows.Scan(&m.Email, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// OrgRole returns a user's role in an org ("" when not a member).
func (s *Store) OrgRole(ctx context.Context, orgID, email string) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx,
		`SELECT role FROM org_members WHERE org_id = ? AND email = ?`, orgID, email).Scan(&role)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return role, err
}

// OrgTokenInfos lists an org's enrollment tokens (labels only, never values).
func (s *Store) OrgTokenInfos(ctx context.Context, orgID string) ([]model.OrgTokenInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, created_at FROM org_tokens WHERE org_id = ? ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.OrgTokenInfo
	for rows.Next() {
		var t model.OrgTokenInfo
		var created int64
		if err := rows.Scan(&t.Name, &created); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, t)
	}
	return out, rows.Err()
}

// OrgAdminCount returns how many members hold the admin role in an org.
func (s *Store) OrgAdminCount(ctx context.Context, orgID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM org_members WHERE org_id = ? AND role = 'admin'`, orgID).Scan(&n)
	return n, err
}

// RemoveOrgMember drops a member from an org. Returns whether the membership
// existed.
func (s *Store) RemoveOrgMember(ctx context.Context, orgID, email string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM org_members WHERE org_id = ? AND email = ?`, orgID, email)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// UserOrgs lists orgs an email belongs to.
func (s *Store) UserOrgs(ctx context.Context, email string) ([]model.Org, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT o.id, o.name, o.created_at FROM orgs o
JOIN org_members m ON m.org_id = o.id WHERE m.email = ? ORDER BY o.name`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Org
	for rows.Next() {
		var o model.Org
		var created int64
		if err := rows.Scan(&o.ID, &o.Name, &created); err != nil {
			return nil, err
		}
		o.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, o)
	}
	return out, rows.Err()
}

// AdminCount returns how many instance admins exist.
func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE is_admin = 1`).Scan(&n)
	return n, err
}

// SetUserAdmin grants or revokes instance-admin status by email. Returns
// whether the user exists.
func (s *Store) SetUserAdmin(ctx context.Context, email string, admin bool) (bool, error) {
	v := 0
	if admin {
		v = 1
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET is_admin = ? WHERE email = ?`, v, email)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// UserIsAdmin reports a user's instance-admin status; ok=false if no such
// user has signed in yet.
func (s *Store) UserIsAdmin(ctx context.Context, email string) (admin, ok bool, err error) {
	var v int
	err = s.db.QueryRowContext(ctx,
		`SELECT is_admin FROM users WHERE email = ?`, email).Scan(&v)
	if err == sql.ErrNoRows {
		return false, false, nil
	}
	return v == 1, true, err
}

// ---- sessions ----

// CreateSession returns a new session token (plaintext; only its hash is
// stored).
func (s *Store) CreateSession(ctx context.Context, userID string, ttl time.Duration, hash func(string) string) (string, error) {
	token, err := randomID(32)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		hash(token), userID, time.Now().Add(ttl).Unix())
	return token, err
}

// SessionUser resolves a session token to its user; ok=false when the session
// is missing or expired.
func (s *Store) SessionUser(ctx context.Context, tokenHash string) (model.User, bool, error) {
	var u model.User
	var isAdmin int
	var expires int64
	err := s.db.QueryRowContext(ctx, `
SELECT u.id, u.email, u.name, u.is_admin, s.expires_at
FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?`, tokenHash).
		Scan(&u.ID, &u.Email, &u.Name, &isAdmin, &expires)
	if err == sql.ErrNoRows {
		return model.User{}, false, nil
	}
	if err != nil {
		return model.User{}, false, err
	}
	if time.Now().Unix() > expires {
		s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, tokenHash)
		return model.User{}, false, nil
	}
	u.Admin = isAdmin == 1
	return u, true, nil
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, tokenHash)
	return err
}

// PruneSessions removes expired sessions.
func (s *Store) PruneSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
	return err
}
