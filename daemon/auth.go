package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// LoadOrCreateToken reads the bearer token from path, or generates a new
// 256-bit token and stores it with mode 0600. The parent directory is
// created with 0700. It refuses to use a token file that is readable by
// group/other.
func LoadOrCreateToken(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if data, err := os.ReadFile(path); err == nil {
		tok := strings.TrimSpace(string(data))
		if fi, serr := os.Stat(path); serr == nil {
			if fi.Mode().Perm()&0o077 != 0 {
				return "", fmt.Errorf("token file %s has loose permissions %o, want 0600", path, fi.Mode().Perm())
			}
		}
		if len(tok) < 32 {
			return "", fmt.Errorf("token file %s holds a token that is too short", path)
		}
		return tok, nil
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b[:])
	// O_EXCL so we never clobber an existing token in a race.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return "", rerr
			}
			return strings.TrimSpace(string(data)), nil
		}
		return "", err
	}
	if _, err := f.WriteString(tok + "\n"); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	// Belt and braces: force 0600 regardless of umask.
	_ = os.Chmod(path, 0o600)
	return tok, nil
}

// bearerAuth is middleware enforcing the permission-gated token.
// Health check (/healthz) is intentionally left open so supervisors can
// probe liveness without the secret; everything else needs the token.
func bearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		got := r.Header.Get("Authorization")
		want := "Bearer " + token
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
