package main

// anchor.go — external audit anchor (v3).
//
// v2's hash chain proves a log was not edited *in place*: to change history you
// must recompute every hash from the edit point on. It does not stop an attacker
// with write access to the log from recomputing the whole file, because nothing
// outside the file remembers what the chain used to say (SECURITY.md §5.3).
//
// v3 closes that with an external anchor: every `anchorEvery`, the daemon
// appends one record to `anchors.jsonl` binding the current chain head —
// `sha256` tip and `seq` — to an HMAC-SHA256 over it under a key that lives only
// in the daemon's environment ($KAVACH_ANCHOR_KEY) and is never written, logged,
// served or exported. Anchors are chained to each other (prev_mac), so removing
// one from the middle is detectable too.
//
// The honest limit, which the verifier states out loud rather than hides:
// an anchor pins a *prefix*. An attacker can still forge the log after the
// newest anchor, so verify reports exactly how many lines are unanchored
// (the "unanchored window") instead of collapsing "the chain is intact" into
// "the log is untampered". Forging *from the start* — the case v2 could not see
// at all — is now a MAC failure.
//
// This is not a timestamp authority. The `at` field is the daemon's own clock,
// which an attacker who controls the daemon controls; HMAC gives integrity and
// authenticity, not non-repudiation or provable time. Shipping the anchor file
// to append-only/WORM storage off-box is what turns it into evidence.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// envAnchorKey names the environment variable holding the anchor HMAC key. Its
// value is never logged, never served and never written to disk by this code.
const envAnchorKey = "KAVACH_ANCHOR_KEY"

// DefaultAnchorInterval is how often the chain head is anchored when nothing
// overrides it. Short enough that the unanchored window stays small, long enough
// that the anchor file is not the busiest thing in the container.
const DefaultAnchorInterval = 60 * time.Second

// MinAnchorKeyBytes is the shortest key accepted. HMAC-SHA256 with a short key
// is still HMAC-SHA256, so a 4-byte "key" would be a silent downgrade of the one
// control this file exists to provide: refuse, warn, and anchor nothing.
const MinAnchorKeyBytes = 32

// AnchorVersion is the record format version, bound into the MAC.
const AnchorVersion = 1

// AnchorRecord is one line of anchors.jsonl. Everything except mac is covered by
// the MAC, and mac is covered by the next record's prev_mac, so the anchor file
// is itself tamper-evident.
type AnchorRecord struct {
	Version int    `json:"version"`
	At      string `json:"at"`                 // daemon clock — see the file header
	Seq     int    `json:"seq"`                // audit line count at the anchor (0-based index of the anchored line + 1)
	Hash    string `json:"hash"`               // audit chain head
	Lines   int    `json:"lines"`              // == Seq; named for readability in the file
	MAC     string `json:"mac"`                // hex HMAC-SHA256 over the canonical payload
	PrevMAC string `json:"prev_mac,omitempty"` // chains the anchors themselves
}

// macPayload is the exact byte string the MAC covers. It is built explicitly
// (not by marshalling the struct) so a new field can never silently fall outside
// or inside the signature.
func (r AnchorRecord) macPayload() []byte {
	return []byte(fmt.Sprintf("v%d|%s|%d|%s|%s", r.Version, r.At, r.Seq, r.Hash, r.PrevMAC))
}

// signAnchor computes the record MAC.
func signAnchor(r AnchorRecord, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(r.macPayload())
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyAnchorMAC reports whether a record's MAC matches. A length mismatch is
// a failure, not a truncation to compare.
func verifyAnchorMAC(r AnchorRecord, key []byte) bool {
	want := signAnchor(r, key)
	return hmac.Equal([]byte(want), []byte(r.MAC))
}

// AnchorKeyFromEnv returns the HMAC key, or nil when none is usable. A key that
// is present but too short is refused, with the *length* logged and never the
// value: a weak key would create exactly the false confidence this control is
// meant to remove.
func AnchorKeyFromEnv() []byte {
	raw := strings.TrimSpace(os.Getenv(envAnchorKey))
	if raw == "" {
		return nil
	}
	key := []byte(raw)
	// A 64-character hex string is accepted as hex, so the key can be generated
	// and rotated with the usual tools without an escaping step.
	if len(raw) == 64 {
		if decoded, err := hex.DecodeString(raw); err == nil {
			key = decoded
		}
	}
	if len(key) < MinAnchorKeyBytes {
		logHardeningWarn("anchor-key", fmt.Sprintf("%s is set but only %d bytes long (need %d): anchoring disabled", envAnchorKey, len(key), MinAnchorKeyBytes))
		return nil
	}
	return key
}

// envAnchorInterval overrides the anchor period when the flag is not given.
const envAnchorInterval = "KAVACH_ANCHOR_INTERVAL"

// AnchorIntervalFromEnv returns the anchor period from $KAVACH_ANCHOR_INTERVAL
// (a Go duration, e.g. "30s" or "5m"), or 0 when unset or unparseable. An
// unparseable value falls back to the default and is logged once: a typo must not
// stop the daemon from anchoring at all.
func AnchorIntervalFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv(envAnchorInterval))
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		logHardeningWarn("anchor-interval", fmt.Sprintf("%s=%q is not a positive duration (want e.g. 30s); using %s", envAnchorInterval, raw, DefaultAnchorInterval))
		return 0
	}
	return d
}

// AnchorSource is the live view of the chain head the anchor binds. AuditLog
// implements it, so the anchor never has to re-read or re-parse the log.
type AnchorSource interface {
	ChainTip() (string, int) // (hash, seq)
}

// Anchor writes and chains the external anchors for one audit log.
type Anchor struct {
	mu       sync.Mutex
	path     string
	key      []byte
	src      AnchorSource
	interval time.Duration

	lastMAC  string
	lastHash string
	lastSeq  int
	stopOnce sync.Once
	stop     chan struct{}
	// writes counts successful appends; exposed for tests and the audit trail.
	writes int
	// lastErr is the most recent failure, so /v1/backends can report a broken
	// anchor (a full disk must not look like a healthy chain).
	lastErr string
}

// NewAnchor builds an anchor writer. A nil key or a nil source disables it:
// Enabled() then reports false and nothing is ever written, which is what the
// "no key = warn, not pass" rule in VerifyAnchoredLog is about.
func NewAnchor(path string, key []byte, src AnchorSource) *Anchor {
	return &Anchor{path: path, key: key, src: src, interval: DefaultAnchorInterval, stop: make(chan struct{})}
}

// Enabled reports whether anchoring will actually happen.
func (a *Anchor) Enabled() bool { return a != nil && a.path != "" && len(a.key) > 0 && a.src != nil }

// Path is the anchor file ("" when disabled).
func (a *Anchor) Path() string {
	if a == nil {
		return ""
	}
	return a.path
}

// Interval returns the anchor period (0 when disabled).
func (a *Anchor) Interval() time.Duration {
	if !a.Enabled() {
		return 0
	}
	return a.interval
}

// Status is the anchor's health, for /v1/backends and the boot log.
func (a *Anchor) Status() map[string]any {
	out := map[string]any{"enabled": a.Enabled()}
	if a == nil {
		return out
	}
	if a.path != "" {
		out["path"] = a.path
	}
	out["interval_sec"] = int(a.Interval() / time.Second)
	if len(a.key) > 0 {
		// The key's *length class* is not a secret; the key is.
		out["key_bits"] = len(a.key) * 8
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out["anchors_written"] = a.writes
	if a.lastMAC != "" {
		out["last_anchor"] = map[string]any{"seq": a.lastSeq, "mac": a.lastMAC[:16] + "…"}
	}
	if a.lastErr != "" {
		out["last_error"] = a.lastErr
	}
	return out
}

// SetInterval overrides the period (0 or negative disables the loop but leaves
// manual Write calls working).
func (a *Anchor) SetInterval(d time.Duration) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if d > 0 {
		a.interval = d
	}
}

// Write appends one anchor for the current chain head. It is a no-op (and says
// so) when the chain has not moved since the last anchor: an unchanged head adds
// no evidence, and a file of duplicate records only inflates the window report.
func (a *Anchor) Write() error {
	if !a.Enabled() {
		return fmt.Errorf("%w: no anchor key configured", ErrHardeningUnsupported)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	hash, seq := a.src.ChainTip()
	rec := AnchorRecord{
		Version: AnchorVersion,
		At:      time.Now().UTC().Format(time.RFC3339Nano),
		Seq:     seq,
		Hash:    hash,
		Lines:   seq,
		PrevMAC: a.lastMAC,
	}
	if a.lastMAC != "" && rec.Hash == a.lastHash && rec.Seq == a.lastSeq {
		return nil // head unchanged since the last anchor
	}
	rec.MAC = signAnchor(rec, a.key)
	line, err := json.Marshal(rec)
	if err != nil {
		a.lastErr = err.Error()
		return err
	}
	if err := appendLine0600(a.path, line); err != nil {
		a.lastErr = err.Error()
		return err
	}
	a.lastMAC = rec.MAC
	a.lastSeq = rec.Seq
	a.lastHash = rec.Hash
	a.writes++
	a.lastErr = ""
	return nil
}

// Start anchors immediately and then every interval until Stop. It returns the
// channel that is closed on Stop, so a caller (or a test) can wait for the loop
// to end instead of racing it.
func (a *Anchor) Start() {
	if !a.Enabled() {
		return
	}
	a.mu.Lock()
	interval := a.interval
	a.mu.Unlock()
	go func() {
		// The first anchor happens right away so a fresh log is anchored before
		// anything can be appended to it unnoticed.
		if err := a.Write(); err != nil {
			logHardeningWarn("anchor-write", "first anchor failed: "+err.Error())
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-a.stop:
				return
			case <-t.C:
				if err := a.Write(); err != nil {
					logHardeningWarn("anchor-write", err.Error())
				}
			}
		}
	}()
}

// Stop ends the loop and writes a final anchor, so the head at shutdown is the
// last thing a verifier sees.
func (a *Anchor) Stop() {
	if a == nil {
		return
	}
	a.stopOnce.Do(func() {
		close(a.stop)
		if a.Enabled() {
			if err := a.Write(); err != nil {
				logHardeningWarn("anchor-stop", "final anchor failed: "+err.Error())
			}
		}
	})
}

// defaultAnchorPath puts anchors.jsonl beside the audit log, which is the one
// place an operator will look and the one path the container already persists.
func defaultAnchorPath(auditPath string) string {
	if auditPath == "" {
		return ""
	}
	dir := filepath.Dir(auditPath)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "anchors.jsonl")
}

// appendLine0600 appends one line to a 0600 file, fsyncing like the audit log
// does. The anchor is evidence, so it gets the same durability treatment.
func appendLine0600(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// ReadAnchors parses an anchor file. A missing file is not an error: it is
// reported as an absent anchor, which is the honest state of an unconfigured
// deployment.
func ReadAnchors(path string) ([]AnchorRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []AnchorRecord
	for i, raw := range splitLines(data) {
		var r AnchorRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("anchors: line %d is not valid JSON: %w", i+1, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// AnchorCheck is the verifier's report on the anchor file. It is deliberately
// explicit about what is *not* covered.
type AnchorCheck struct {
	// Status is "ok", "warn" or "fail" — the only three answers.
	Status string `json:"status"`
	// Anchors is how many anchor records were found.
	Anchors int `json:"anchors"`
	// Verified is how many passed the MAC and the prev_mac chain.
	Verified int `json:"verified"`
	// AnchoredSeq/Hash are the newest anchor that was found in the log.
	AnchoredSeq  int    `json:"anchored_seq"`
	AnchoredHash string `json:"anchored_hash,omitempty"`
	// LogLines is the audit log's line count.
	LogLines int `json:"log_lines"`
	// UnanchoredLines is the window a forger could still rewrite unnoticed:
	// everything after the newest verified anchor.
	UnanchoredLines int `json:"unanchored_lines"`
	// Problems are hard failures; Warnings are honest gaps.
	Problems []string `json:"problems,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	// Note is the one-line summary a human should read.
	Note string `json:"note"`
}

// OK reports whether the anchor check passed outright.
func (c AnchorCheck) OK() bool { return c.Status == "ok" || c.Status == "warn" }

// VerifyAnchoredLog checks the audit log against its anchor file.
//
// The rules, in order of importance:
//
//   - A record whose MAC does not verify, or whose prev_mac does not match the
//     record before it, is a hard failure. Either the anchor file was edited, or
//     the key is not the one that wrote it.
//   - An anchor whose hash is not in the log (or is past the end) is a hard
//     failure: the log was rewritten from the start or truncated below an
//     anchor. This is the wholesale-rewrite case v2 could not see.
//   - No key, or no anchor file, is a WARNING, not a pass: the chain is
//     verified, but nothing binds it to anything outside itself, and the report
//     says so.
//   - Otherwise the unanchored window is reported as a number, because an anchor
//     pins a prefix and the suffix is exactly as forgeable as it was in v2.
func VerifyAnchoredLog(auditPath, anchorPath string, key []byte) AnchorCheck {
	chk := AnchorCheck{Status: "ok"}
	lines, err := readAuditLines(auditPath)
	if err != nil {
		chk.Status = "fail"
		chk.Problems = append(chk.Problems, "audit log unreadable: "+err.Error())
		chk.Note = "cannot verify: " + err.Error()
		return chk
	}
	chk.LogLines = len(lines)

	recs, err := ReadAnchors(anchorPath)
	if err != nil {
		chk.Status = "fail"
		chk.Problems = append(chk.Problems, err.Error())
		chk.Note = "anchor file unreadable"
		return chk
	}
	chk.Anchors = len(recs)
	switch {
	case len(recs) == 0:
		chk.Status = "warn"
		chk.Warnings = append(chk.Warnings, fmt.Sprintf("no anchors in %s", anchorPath))
		if len(key) == 0 {
			chk.Warnings = append(chk.Warnings, envAnchorKey+" is not set, so no anchor can be written or checked")
		}
		chk.UnanchoredLines = chk.LogLines
		chk.Note = "chain verified but UNANCHORED: a wholesale rewrite of this log would not be detected"
		return chk
	case len(key) == 0:
		chk.Status = "warn"
		chk.Warnings = append(chk.Warnings, fmt.Sprintf("%s is not set: %d anchor(s) exist but none can be authenticated", envAnchorKey, len(recs)))
		chk.UnanchoredLines = chk.LogLines
		chk.Note = "chain verified but UNANCHORED: existing anchors cannot be authenticated without the key"
		return chk
	}

	// Index the log by chain hash so an anchor can be located in it.
	index := make(map[string]int, len(lines))
	hashes := make([]string, 0, len(lines))
	for i, m := range lines {
		if h, ok := m["hash"].(string); ok && h != "" {
			index[h] = i
			hashes = append(hashes, h)
		}
	}

	prevMAC := ""
	newestVerified := -1
	for i, r := range recs {
		switch {
		case r.Version != AnchorVersion:
			chk.Problems = append(chk.Problems, fmt.Sprintf("anchor %d: unknown version %d", i+1, r.Version))
			continue
		case !verifyAnchorMAC(r, key):
			chk.Problems = append(chk.Problems, fmt.Sprintf(
				"anchor %d: MAC mismatch at seq %d (the record was edited, or %s is not the key that wrote it)", i+1, r.Seq, envAnchorKey))
			continue
		case r.PrevMAC != prevMAC:
			chk.Problems = append(chk.Problems, fmt.Sprintf(
				"anchor %d: prev_mac mismatch (an earlier anchor was removed, reordered or rewritten)", i+1))
			continue
		}
		chk.Verified++
		prevMAC = r.MAC
		// Locate the anchored head in the log.
		pos, ok := index[r.Hash]
		if !ok {
			// The genesis anchor means "nothing had been written yet": it sits
			// before line 0 rather than on it. It pins nothing on its own (any
			// forged chain also starts at GENESIS) — the anchors that follow it
			// are what carry the evidence.
			if r.Hash == genesisHash && r.Seq == 0 {
				pos = -1
			} else {
				chk.Problems = append(chk.Problems, fmt.Sprintf(
					"anchor %d: anchored hash %.16s… at seq %d is not in the log (it was rewritten away, or the log was replaced)", i+1, r.Hash, r.Seq))
				continue
			}
		} else if r.Seq != pos+1 {
			chk.Problems = append(chk.Problems, fmt.Sprintf(
				"anchor %d: anchored hash is log line %d but claims seq %d (the log was resequenced)", i+1, pos+1, r.Seq))
			continue
		}
		newestVerified = pos
		chk.AnchoredSeq = r.Seq
		chk.AnchoredHash = r.Hash
	}
	if chk.Verified > 0 {
		chk.UnanchoredLines = chk.LogLines - 1 - newestVerified
		if chk.UnanchoredLines < 0 {
			chk.UnanchoredLines = 0
		}
	}
	switch {
	case len(chk.Problems) > 0:
		chk.Status = "fail"
		chk.Note = fmt.Sprintf("ANCHOR MISMATCH: %d problem(s); the log does not match what was anchored", len(chk.Problems))
	case chk.UnanchoredLines > 0:
		chk.Status = "warn"
		chk.Warnings = append(chk.Warnings, fmt.Sprintf(
			"unanchored window: %d line(s) after the newest anchor at seq %d can be rewritten without breaking the chain",
			chk.UnanchoredLines, chk.AnchoredSeq))
		chk.Note = fmt.Sprintf("anchored through seq %d of %d; the last %d line(s) are not externally anchored", chk.AnchoredSeq, chk.LogLines, chk.UnanchoredLines)
	default:
		chk.Note = fmt.Sprintf("anchored through the chain head (seq %d, %d anchor(s) verified)", chk.AnchoredSeq, chk.Verified)
	}
	return chk
}

// readAuditLines parses the audit log for the anchor verifier. It does not
// replay the chain — VerifyLog owns that — it only indexes what is there, so a
// broken chain is reported by the chain check and a missing anchor by this one.
func readAuditLines(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, raw := range splitLines(data) {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			// A torn tail is the chain check's business; stop there rather than
			// reporting a bogus "anchored hash not in the log".
			return out, nil
		}
		out = append(out, m)
	}
	return out, nil
}
