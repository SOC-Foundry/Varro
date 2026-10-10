package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Off-VM database backups to Google Cloud Storage. The collector's config and
// audit trail (orgs, members, tokens, users, sessions, audit log) are the
// durable, hard-to-reconstruct state; telemetry is ephemeral. A snapshot is
// taken with VACUUM INTO (consistent on a live DB) and uploaded using the
// VM's metadata service-account token — no key files, no gsutil.

type BackupConfig struct {
	GCS      string // gs://bucket/prefix
	Interval time.Duration
}

func (s *Server) backupEnabled() bool { return s.cfg.Backup.GCS != "" }

// backupLoop runs one backup shortly after startup (for immediate
// verification) and then every Interval.
func (s *Server) backupLoop(ctx context.Context) {
	timer := time.NewTimer(60 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := s.runBackup(ctx); err != nil {
			s.log.Error("backup failed", "error", err)
		}
		iv := s.cfg.Backup.Interval
		if iv <= 0 {
			iv = 24 * time.Hour
		}
		timer.Reset(iv)
	}
}

func parseGCS(u string) (bucket, prefix string, err error) {
	rest, ok := strings.CutPrefix(u, "gs://")
	if !ok {
		return "", "", fmt.Errorf("backup target must be gs://bucket[/prefix]")
	}
	bucket = rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		bucket = rest[:i]
		prefix = strings.Trim(rest[i+1:], "/")
	}
	return bucket, prefix, nil
}

func (s *Server) runBackup(ctx context.Context) error {
	bucket, prefix, err := parseGCS(s.cfg.Backup.GCS)
	if err != nil {
		return err
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("varro-backup-%d.db", time.Now().UnixNano()))
	if err := s.store.BackupTo(tmp); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	defer os.Remove(tmp)
	data, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}

	token, err := metadataToken(ctx)
	if err != nil {
		return fmt.Errorf("metadata token (is the VM scoped for storage write?): %w", err)
	}
	object := time.Now().UTC().Format("20060102T150405Z") + ".db"
	if prefix != "" {
		object = prefix + "/" + object
	}
	uploadURL := fmt.Sprintf(
		"https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
		url.PathEscape(bucket), url.QueryEscape(object))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-sqlite3")
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GCS upload returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	s.log.Info("backup uploaded", "bucket", bucket, "object", object, "bytes", len(data))
	return nil
}

// metadataToken fetches an access token for the VM's service account.
func metadataToken(ctx context.Context) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %s", resp.Status)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("metadata returned no access token")
	}
	return out.AccessToken, nil
}
