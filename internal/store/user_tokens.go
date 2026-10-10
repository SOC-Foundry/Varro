package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/soc-foundry/varro/internal/model"
)

// ---- personal API tokens ----
//
// A personal API token lets a signed-in user drive the CLI/API without the
// shared master token. Only the SHA-256 hash is stored; the plaintext is shown
// exactly once at creation. The token carries no scope of its own — every
// request resolves the owning user's CURRENT scope, so revoking the user's
// admin rights or org membership narrows the token immediately.

// CreateUserToken mints a personal API token for a user. It returns the
// plaintext token (shown once) and a short public id used to list/revoke it.
func (s *Store) CreateUserToken(ctx context.Context, userID, email, name string, hash func(string) string) (token, id string, err error) {
	token, err = randomID(32)
	if err != nil {
		return "", "", err
	}
	id, err = randomID(6)
	if err != nil {
		return "", "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO user_tokens (token_hash, id, user_id, email, name, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		hash(token), id, userID, email, name, time.Now().Unix())
	return token, id, err
}

// UserForToken resolves a personal API token hash to its owning user, with the
// user's current admin status. ok=false if no such token exists. Best-effort
// updates last_used for the token-management UI.
func (s *Store) UserForToken(ctx context.Context, tokenHash string) (model.User, bool, error) {
	var u model.User
	var isAdmin int
	err := s.db.QueryRowContext(ctx, `
SELECT u.id, u.email, u.name, u.is_admin
FROM user_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?`, tokenHash).
		Scan(&u.ID, &u.Email, &u.Name, &isAdmin)
	if err == sql.ErrNoRows {
		return model.User{}, false, nil
	}
	if err != nil {
		return model.User{}, false, err
	}
	u.Admin = isAdmin == 1
	s.db.ExecContext(ctx, `UPDATE user_tokens SET last_used = ? WHERE token_hash = ?`,
		time.Now().Unix(), tokenHash)
	return u, true, nil
}

// UserTokenInfos lists a user's personal API tokens (labels only, never values).
func (s *Store) UserTokenInfos(ctx context.Context, userID string) ([]model.UserTokenInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, created_at, last_used FROM user_tokens WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.UserTokenInfo
	for rows.Next() {
		var t model.UserTokenInfo
		var created, lastUsed int64
		if err := rows.Scan(&t.ID, &t.Name, &created, &lastUsed); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(created, 0)
		if lastUsed > 0 {
			lu := time.Unix(lastUsed, 0)
			t.LastUsed = &lu
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteUserToken revokes a personal API token by its public id, scoped to its
// owner so a user can only revoke their own. Returns whether a row was removed.
func (s *Store) DeleteUserToken(ctx context.Context, userID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM user_tokens WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
