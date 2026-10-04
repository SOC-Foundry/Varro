package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const gmailScope = "https://www.googleapis.com/auth/gmail.send"

type saKey struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// sendViaGmail delivers one message through the Gmail API, impersonating
// SendAs via a service-account JWT (domain-wide delegation).
func (s *Server) sendViaGmail(to []string, subject, body string) {
	if err := s.gmailSend(to, subject, body); err != nil {
		s.log.Error("gmail send failed", "error", err)
		return
	}
	s.log.Info("email sent via gmail api", "to", to, "subject", subject)
}

func (s *Server) gmailSend(to []string, subject, body string) error {
	raw, err := os.ReadFile(s.cfg.Gmail.SAKeyPath)
	if err != nil {
		return fmt.Errorf("read service-account key: %w", err)
	}
	var key saKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return fmt.Errorf("parse service-account key: %w", err)
	}
	if key.TokenURI == "" {
		key.TokenURI = "https://oauth2.googleapis.com/token"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	token, err := exchangeJWT(ctx, key, s.cfg.Gmail.SendAs)
	if err != nil {
		return fmt.Errorf("token exchange: %w", err)
	}

	msg := "From: Varro <" + s.cfg.Gmail.SendAs + ">\r\n" +
		"To: " + strings.Join(to, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body + "\r\n"
	payload, _ := json.Marshal(map[string]string{
		"raw": base64.RawURLEncoding.EncodeToString([]byte(msg)),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
		bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("gmail api %s: %s", resp.Status, e.Error.Message)
	}
	return nil
}

// exchangeJWT signs a service-account assertion (with sub= the impersonated
// user) and trades it for an access token.
func exchangeJWT(ctx context.Context, key saKey, subject string) (string, error) {
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("service-account key is not RSA")
	}

	now := time.Now()
	b64 := func(v any) string {
		j, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(j)
	}
	signing := b64(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." +
		b64(map[string]any{
			"iss":   key.ClientEmail,
			"sub":   subject,
			"scope": gmailScope,
			"aud":   key.TokenURI,
			"iat":   now.Unix(),
			"exp":   now.Add(5 * time.Minute).Unix(),
		})
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	assertion := signing + "." + base64.RawURLEncoding.EncodeToString(sig)

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, key.TokenURI,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("%s: %s (is domain-wide delegation authorized for this client ID?)", out.Error, out.ErrorDesc)
	}
	return out.AccessToken, nil
}
