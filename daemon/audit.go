package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditLog is an append-only JSONL record of every security-relevant event:
// run submitted/started/finished/killed, kill-switch transitions, auth
// failures. One line = one JSON object, fsynced per write.
//
// v2 tamper evidence: every line carries `seq` (0-based), `prev_hash` (the
// previous line's `hash`, or "GENESIS" for the first chained line) and
// `hash = sha256(prev_hash + "\n" + canonical_body)` where canonical_body is
// the JSON of the entry without the chain fields (Go maps marshal with
// sorted keys, so this is deterministic). VerifyLog replays the chain;
// `daemon -verify audit.jsonl` exits 1 on any edit or torn tail.
//
// Migration: pre-v2 lines without chain fields are accepted as a trusted
// "legacy prefix" only before the first chained line. A legacy-shaped line
// after chaining has started fails verification.

const genesisHash = "GENESIS"

// AuditLog is the append-only, hash-chained security ledger.
type AuditLog struct {
	mu       sync.Mutex
	path     string
	lastHash string
	seq      int
	// secrets returns the current secret *values* to scrub from every field.
	// It is a live lookup, not a snapshot, so an env var exported after boot is
	// still redacted. Nil means "no vault bound" (nothing to scrub).
	secrets func() []string
}

func OpenAuditLog(path string) (*AuditLog, error) {
	return OpenAuditLogRedacted(path, nil)
}

// OpenAuditLogRedacted is OpenAuditLog with a live secret source. Redaction
// lives here rather than only at the call sites so no future caller can leak a
// credential by forgetting to scrub: Append masks every value in every field,
// recursively, before the entry is hashed and written.
func OpenAuditLogRedacted(path string, secrets func() []string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	a := &AuditLog{path: path, lastHash: genesisHash, secrets: secrets}
	tip, seq, err := scanTip(path)
	if err != nil {
		return nil, err
	}
	a.lastHash = tip
	a.seq = seq
	return a, nil
}

// scanTip returns the hash of the last chained line and the next sequence
// number, counting legacy lines too so seq stays dense across upgrades.
// A torn (unparseable) tail is a hard error: fail closed, never append past
// corruption.
func scanTip(path string) (string, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	tip := genesisHash
	seq := 0
	for i, line := range splitLines(data) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return "", 0, fmt.Errorf("audit log corrupt at line %d: %w", i+1, err)
		}
		seq++
		if h, ok := m["hash"].(string); ok && h != "" {
			tip = h
		}
	}
	return tip, seq, nil
}

// chainHash computes the tamper-evident hash for a body chained after prev.
func chainHash(prev string, body []byte) string {
	sum := sha256.Sum256([]byte(prev + "\n" + string(body)))
	return hex.EncodeToString(sum[:])
}

// Append writes one audit entry and fsyncs. Field values are redacted first:
// only [REDACTED] ever reaches disk, so a command that echoes its own
// credentials cannot persist them in the ledger.
func (a *AuditLog) Append(event string, fields map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry := map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano), "event": event}
	for k, v := range fields {
		entry[k] = v
	}
	if a.secrets != nil {
		// Single scrub of the merged entry: a secret may arrive in the event
		// name, a top-level field, or nested inside a list/map.
		entry = RedactMap(entry, a.secrets())
	}
	entry["seq"] = a.seq
	entry["prev_hash"] = a.lastHash
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	entry["hash"] = chainHash(a.lastHash, body)
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	a.lastHash = entry["hash"].(string)
	a.seq++
	return nil
}

// ReadAll parses the whole log back (used by tests and the replay view).
func (a *AuditLog) ReadAll() ([]map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	data, err := os.ReadFile(a.path)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, line := range splitLines(data) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// VerifyLog replays the hash chain in path. It returns nil for a valid chain
// (including empty logs and legacy-prefix logs) and a descriptive error for
// the first broken line: edited content, relinked prev_hash, resequence, a
// legacy line after chaining started, or a torn (unparseable) tail.
func VerifyLog(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := splitLines(data)
	// A file with content but no trailing newline lost its tail bytes.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return fmt.Errorf("torn tail: last line is not newline-terminated (truncated write?)")
	}
	prev := genesisHash
	chained := false
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return fmt.Errorf("line %d: torn tail / invalid JSON: %w", i+1, err)
		}
		h, hasHash := m["hash"].(string)
		ph, hasPrev := m["prev_hash"].(string)
		if !hasHash || !hasPrev || h == "" || ph == "" {
			if chained {
				return fmt.Errorf("line %d: unchained entry after chaining started (tamper?)", i+1)
			}
			continue // trusted legacy prefix
		}
		chained = true
		if ph != prev {
			return fmt.Errorf("line %d: prev_hash mismatch (want %.12s…, got %.12s…)", i+1, prev, ph)
		}
		body := map[string]any{}
		for k, v := range m {
			if k == "hash" {
				continue
			}
			body[k] = v
		}
		canonical, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("line %d: %w", i+1, err)
		}
		if want := chainHash(prev, canonical); want != h {
			return fmt.Errorf("line %d: hash mismatch — entry was edited (want %.12s…, got %.12s…)", i+1, want, h)
		}
		prev = h
	}
	return nil
}

// ChainTip returns the current tip hash and next seq (for tests/diagnostics).
func (a *AuditLog) ChainTip() (string, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastHash, a.seq
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
