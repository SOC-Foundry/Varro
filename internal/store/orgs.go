package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at FROM orgs ORDER BY name`)
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

// OrgByRef resolves an org by ID or (unique) name.
func (s *Store) OrgByRef(ctx context.Context, ref string) (model.Org, error) {
	var o model.Org
	var created int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, created_at FROM orgs WHERE id = ? OR name = ?`, ref, ref).
		Scan(&o.ID, &o.Name, &created)
	if err == sql.ErrNoRows {
		return model.Org{}, fmt.Errorf("no org %q", ref)
	}
	if err != nil {
		return model.Org{}, err
	}
	o.CreatedAt = time.Unix(created, 0).UTC()
	return o, nil
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
