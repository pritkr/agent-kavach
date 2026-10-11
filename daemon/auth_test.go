package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateTokenCreates0600(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "kavach.token")
	tok, err := LoadOrCreateToken(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 32 {
		t.Fatalf("token too short: %q", tok)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("token perms = %o, want 600", fi.Mode().Perm())
	}
	dirFi, _ := os.Stat(filepath.Join(dir, "sub"))
	if dirFi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("parent dir perms = %o, want 700", dirFi.Mode().Perm())
	}
}

func TestLoadOrCreateTokenReloadsSame(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kavach.token")
	a, err := LoadOrCreateToken(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateToken(p)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("token changed between loads")
	}
}

func TestLoadOrCreateTokenRejectsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "kavach.token")
	if err := os.WriteFile(p, []byte("0123456789abcdef0123456789abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(p); err == nil {
		t.Fatal("expected error for 0644 token file")
	}
}

func TestBearerAuthMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := bearerAuth("secret-token", next)

	// /healthz is open
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("healthz code = %d, want 200", rec.Code)
	}

	// missing token -> 401
	req = httptest.NewRequest("GET", "/v1/runs", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("no-token code = %d, want 401", rec.Code)
	}

	// wrong token -> 401
	req = httptest.NewRequest("GET", "/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("wrong-token code = %d, want 401", rec.Code)
	}

	// right token -> 200
	req = httptest.NewRequest("GET", "/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("good-token code = %d, want 200", rec.Code)
	}
}
