package main

// anchor_test.go — the external audit anchor (v3).
//
// The v2 chain detects an edit but not a rewrite: an attacker with write access
// can recompute every hash and `-verify` says OK. These tests pin down the v3
// behaviour in both directions — the wholesale rewrite is now caught, and the
// gaps that remain (the unanchored window, a missing key) are reported as gaps
// rather than as passes.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testAnchorKey is a 32-byte key. It exists only in this file: the daemon reads
// the real one from the environment and never writes it anywhere.
var testAnchorKey = []byte("kavach-test-anchor-key-32-bytes!")

// The key must be exactly the minimum length, so that hex-encoding it produces
// the 64 characters AnchorKeyFromEnv decodes. Getting this wrong silently turns
// the fixture key into a *different* key and every CLI test into a false
// failure, so it is asserted rather than counted by hand.
func init() {
	if len(testAnchorKey) != MinAnchorKeyBytes {
		panic("test anchor key must be exactly MinAnchorKeyBytes")
	}
	if len(hex.EncodeToString(testAnchorKey)) != 64 {
		panic("test anchor key must hex-encode to 64 characters")
	}
}

// setTestAnchorKey puts the fixture key in the environment, which is where the
// daemon (and therefore -verify) reads it from. Tests that exercise the CLI path
// must do this: a verifier with no key is *supposed* to warn, so forgetting it
// would make a real failure look like a pass.
func setTestAnchorKey(t *testing.T) {
	t.Helper()
	t.Setenv(envAnchorKey, hex.EncodeToString(testAnchorKey))
}

// anchorFixture builds an audit log with n entries plus an anchored path.
type anchorFixture struct {
	audit  string
	anchor string
	log    *AuditLog
	anc    *Anchor
}

func newAnchorFixture(t *testing.T, entries int) *anchorFixture {
	t.Helper()
	dir := t.TempDir()
	f := &anchorFixture{
		audit:  filepath.Join(dir, "audit.jsonl"),
		anchor: filepath.Join(dir, "anchors.jsonl"),
	}
	log, err := OpenAuditLog(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	f.log = log
	f.anc = NewAnchor(f.anchor, testAnchorKey, log)
	for i := 0; i < entries; i++ {
		if err := log.Append("run.finished", map[string]any{"run_id": fmt.Sprintf("r%d", i), "status": "done"}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// 1. The happy path: an anchor binds the current chain head, and verification
// says so. Without this, every other test here would be testing a broken control.
func TestAnchorWritesAndVerifies(t *testing.T) {
	f := newAnchorFixture(t, 3)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	recs, err := ReadAnchors(f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("anchors=%d want 1", len(recs))
	}
	rec := recs[0]
	tip, seq := f.log.ChainTip()
	if rec.Hash != tip || rec.Seq != seq {
		t.Fatalf("anchor %d/%s does not match the chain head %d/%s", rec.Seq, rec.Hash, seq, tip)
	}
	if rec.Lines != 3 || rec.Version != AnchorVersion {
		t.Fatalf("unexpected record: %+v", rec)
	}
	// The file is 0600, like the audit log: an anchor is evidence.
	fi, err := os.Stat(f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("anchor perms=%o want 600", fi.Mode().Perm())
	}
	chk := VerifyAnchoredLog(f.audit, f.anchor, testAnchorKey)
	if !chk.OK() || chk.Status != "ok" {
		t.Fatalf("a fresh anchor must verify clean: %+v", chk)
	}
	if chk.Verified != 1 || chk.AnchoredSeq != 3 || chk.UnanchoredLines != 0 {
		t.Fatalf("unexpected check: %+v", chk)
	}
}

// 2. The v2 attack, now caught: rewrite the whole log with recomputed hashes.
// This is the case SECURITY.md §5.3 said was undetectable.
func TestAnchorDetectsWholesaleRewrite(t *testing.T) {
	f := newAnchorFixture(t, 4)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	// Forge: rebuild the log from scratch with different content, chaining the
	// hashes properly. VerifyLog alone passes this — that is the point.
	forged := forgeChain(t, []map[string]any{
		{"event": "run.finished", "status": "failed", "note": "never happened"},
		{"event": "run.finished", "status": "done"},
	})
	if err := os.WriteFile(f.audit, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLog(f.audit); err != nil {
		t.Fatalf("test setup: the forged chain should pass the v2 check, got %v", err)
	}
	chk := VerifyAnchoredLog(f.audit, f.anchor, testAnchorKey)
	if chk.Status != "fail" {
		t.Fatalf("a wholesale rewrite must fail the anchor check: %+v", chk)
	}
	if !strings.Contains(strings.Join(chk.Problems, " "), "not in the log") {
		t.Fatalf("the problem must say the anchored head is gone: %v", chk.Problems)
	}
	// And the CLI must exit non-zero for it.
	setTestAnchorKey(t)
	var out, errOut bytes.Buffer
	if code := runVerify(f.audit, f.anchor, &out, &errOut); code != 1 {
		t.Fatalf("exit=%d want 1 for an anchor mismatch", code)
	}
	if !strings.Contains(errOut.String(), "ANCHOR MISMATCH") {
		t.Fatalf("missing the mismatch banner: %q", errOut.String())
	}
	if strings.Contains(out.String(), "audit chain OK") == false {
		t.Fatalf("the chain itself was intact, so the chain line should be there too: %q", out.String())
	}
}

// forgeChain builds a valid, internally consistent hash chain from bodies. It is
// the attacker's tool: correct hashes, wrong history.
func forgeChain(t *testing.T, bodies []map[string]any) []byte {
	t.Helper()
	prev := genesisHash
	var buf bytes.Buffer
	for i, body := range bodies {
		entry := map[string]any{"at": "2026-01-01T00:00:00Z", "seq": i, "prev_hash": prev}
		for k, v := range body {
			entry[k] = v
		}
		canonical, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		h := chainHash(prev, canonical)
		entry["hash"] = h
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
		prev = h
	}
	return buf.Bytes()
}

// 3. An edited anchor record is caught by its MAC — and so is a *different* key,
// which is why the key is worth protecting.
func TestAnchorDetectsEditedRecordAndWrongKey(t *testing.T) {
	f := newAnchorFixture(t, 2)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	// Edit the anchored seq: the classic "make the forgery look older" move.
	edited := strings.Replace(string(raw), fmt.Sprintf(`"seq":%d`, 2), `"seq":1`, 1)
	if edited == string(raw) {
		t.Fatal("test setup: seq not found in the anchor record")
	}
	if err := os.WriteFile(f.anchor, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	chk := VerifyAnchoredLog(f.audit, f.anchor, testAnchorKey)
	if chk.Status != "fail" || !strings.Contains(strings.Join(chk.Problems, " "), "MAC mismatch") {
		t.Fatalf("an edited anchor must fail on its MAC: %+v", chk)
	}
	// The right chain with the wrong key is also a failure, never a pass.
	chk = VerifyAnchoredLog(f.audit, f.anchor, []byte("a-completely-different-key-32byte"))
	if chk.Status != "fail" {
		t.Fatalf("a wrong key must not verify: %+v", chk)
	}
	// A key of the right length but wrong bytes is the same case.
	chk = VerifyAnchoredLog(f.audit, f.anchor, testAnchorKeyPlusOne())
	if chk.Status != "fail" {
		t.Fatalf("a tampered key must not verify: %+v", chk)
	}
}

func testAnchorKeyPlusOne() []byte {
	k := append([]byte(nil), testAnchorKey...)
	k[0] ^= 0xff
	return k
}

// 4. Anchors are chained to each other, so removing one from the middle is
// detectable — a per-record MAC alone would not catch that.
func TestAnchorDetectsRemovedRecord(t *testing.T) {
	f := newAnchorFixture(t, 3)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	_ = f.log.Append("run.killed", map[string]any{"run_id": "rx"})
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 anchors, got %d", len(lines))
	}
	// Drop the first one. Its successor's prev_mac now points at nothing.
	if err := os.WriteFile(f.anchor, []byte(lines[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chk := VerifyAnchoredLog(f.audit, f.anchor, testAnchorKey)
	if chk.Status != "fail" || !strings.Contains(strings.Join(chk.Problems, " "), "prev_mac") {
		t.Fatalf("a removed anchor must break the chain: %+v", chk)
	}
}

// 5. The MAC covers a stable, explicit payload, and the anchors chain: two
// anchors in a row must link, and the payload must include every field that
// matters (a field outside the signature would be a field an attacker owns).
func TestAnchorChainAndPayloadCoverage(t *testing.T) {
	f := newAnchorFixture(t, 2)
	for i := 0; i < 2; i++ {
		if i == 1 {
			_ = f.log.Append("run.finished", map[string]any{"run_id": "later"})
		}
		if err := f.anc.Write(); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := ReadAnchors(f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("anchors=%d want 2", len(recs))
	}
	if recs[0].PrevMAC != "" {
		t.Fatal("the first anchor cannot have a predecessor")
	}
	if recs[1].PrevMAC != recs[0].MAC {
		t.Fatal("the second anchor must chain to the first")
	}
	// Recompute a MAC by hand over the documented payload.
	mac := hmac.New(sha256.New, testAnchorKey)
	mac.Write(recs[0].macPayload())
	if hex.EncodeToString(mac.Sum(nil)) != recs[0].MAC {
		t.Fatal("the MAC does not match v|at|seq|hash|prev_mac")
	}
	if !strings.Contains(string(recs[0].macPayload()), recs[0].Hash) {
		t.Fatal("the payload must cover the anchored hash")
	}
	// The MAC field itself is not in the payload, or it would be circular.
	if strings.Contains(string(recs[0].macPayload()), recs[0].MAC) {
		t.Fatal("the MAC must not cover itself")
	}
}

// 6. An unchanged head is not re-anchored: duplicates add no evidence and would
// make the unanchored-window report meaningless.
func TestAnchorSkipsDuplicateHeads(t *testing.T) {
	f := newAnchorFixture(t, 2)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := f.anc.Write(); err != nil {
			t.Fatal(err)
		}
	}
	recs, _ := ReadAnchors(f.anchor)
	if len(recs) != 1 {
		t.Fatalf("an unchanged chain head must not be re-anchored, got %d records", len(recs))
	}
	// Once the log moves, the next anchor appears.
	_ = f.log.Append("run.finished", map[string]any{"run_id": "new"})
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	recs, _ = ReadAnchors(f.anchor)
	if len(recs) != 2 || recs[1].PrevMAC != recs[0].MAC {
		t.Fatalf("a moved head must produce a chained second anchor: %+v", recs)
	}
}

// 7. The unanchored window is reported as a number, because an anchor pins a
// prefix and the suffix is as forgeable as it was in v2. A verifier that hides
// this is worse than one without anchors.
func TestAnchorReportsTheUnanchoredWindow(t *testing.T) {
	f := newAnchorFixture(t, 3)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_ = f.log.Append("run.finished", map[string]any{"run_id": fmt.Sprintf("after%d", i)})
	}
	chk := VerifyAnchoredLog(f.audit, f.anchor, testAnchorKey)
	if chk.Status != "warn" {
		t.Fatalf("an unanchored tail must be a warning, not a clean pass: %+v", chk)
	}
	if chk.UnanchoredLines != 5 {
		t.Fatalf("unanchored=%d want 5 (everything after the anchor)", chk.UnanchoredLines)
	}
	if !strings.Contains(strings.Join(chk.Warnings, " "), "unanchored window") {
		t.Fatalf("the warning must name the window: %v", chk.Warnings)
	}
	if !strings.Contains(chk.Note, "not externally anchored") {
		t.Fatalf("the note must be explicit: %q", chk.Note)
	}
	// And the CLI must exit 0 (the chain is intact) while saying all of this on
	// stderr, never on stdout.
	setTestAnchorKey(t)
	var out, errOut bytes.Buffer
	if code := runVerify(f.audit, f.anchor, &out, &errOut); code != 0 {
		t.Fatalf("exit=%d want 0: an unanchored tail is not chain damage", code)
	}
	if !strings.Contains(errOut.String(), "WARNING") || !strings.Contains(errOut.String(), "5 line(s)") {
		t.Fatalf("stderr must carry the warning: %q", errOut.String())
	}
	if strings.Contains(out.String(), "WARNING") {
		t.Fatal("warnings belong on stderr, not in the result")
	}
}

// 8. No key means the log is UNANCHORED, and that is a warning — never a pass,
// never a silent one. The message has to name the environment variable, or the
// operator cannot act on it.
func TestAnchorMissingKeyIsWarnNotPass(t *testing.T) {
	f := newAnchorFixture(t, 2)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	// Anchors exist but no key: they cannot be authenticated.
	chk := VerifyAnchoredLog(f.audit, f.anchor, nil)
	if chk.Status != "warn" {
		t.Fatalf("a missing key must warn, got %q: %+v", chk.Status, chk)
	}
	if !strings.Contains(strings.Join(chk.Warnings, " "), envAnchorKey) {
		t.Fatalf("the warning must name %s: %v", envAnchorKey, chk.Warnings)
	}
	if !strings.Contains(chk.Note, "UNANCHORED") {
		t.Fatalf("the note must say UNANCHORED: %q", chk.Note)
	}
	if chk.UnanchoredLines != 2 {
		t.Fatalf("with no key nothing is anchored, so the window is the whole log: %+v", chk)
	}

	// No anchor file at all: same verdict, and the same demand to be told.
	empty := filepath.Join(t.TempDir(), "anchors.jsonl")
	chk = VerifyAnchoredLog(f.audit, empty, testAnchorKey)
	if chk.Status != "warn" || !strings.Contains(strings.Join(chk.Warnings, " "), "no anchors") {
		t.Fatalf("a missing anchor file must warn: %+v", chk)
	}

	// The CLI: exit 0 (nothing is damaged) with a WARNING on stderr.
	var out, errOut bytes.Buffer
	if code := runVerify(f.audit, f.anchor, &out, &errOut); code != 0 {
		t.Fatalf("exit=%d want 0", code)
	}
	if !strings.Contains(errOut.String(), "UNANCHORED") {
		t.Fatalf("stderr must say UNANCHORED: %q", errOut.String())
	}
	if strings.Contains(out.String(), "anchors OK") {
		t.Fatalf("stdout must not claim the anchors are fine: %q", out.String())
	}
}

// 9. A weak key is refused rather than used: HMAC with a 4-byte key is still
// HMAC, which is exactly the kind of false confidence this control must not
// create. The *value* is never logged, only the length.
func TestAnchorKeyPolicy(t *testing.T) {
	t.Setenv(envAnchorKey, "")
	if k := AnchorKeyFromEnv(); k != nil {
		t.Fatal("an unset key must disable anchoring")
	}
	// A 64-char hex string is decoded, so a key from `openssl rand -hex 32`
	// works without an escaping step.
	t.Setenv(envAnchorKey, strings.Repeat("ab", 32))
	k := AnchorKeyFromEnv()
	if len(k) != 32 {
		t.Fatalf("hex key should decode to 32 bytes, got %d", len(k))
	}
	// Too short: refused.
	t.Setenv(envAnchorKey, "short")
	if k := AnchorKeyFromEnv(); k != nil {
		t.Fatal("a key below the minimum length must be refused")
	}
	// 31 bytes is still refused, 32 is not.
	t.Setenv(envAnchorKey, strings.Repeat("x", MinAnchorKeyBytes-1))
	if k := AnchorKeyFromEnv(); k != nil {
		t.Fatal("a one-byte-short key must be refused")
	}
	// An anchor with no key writes nothing at all.
	f := newAnchorFixture(t, 1)
	none := NewAnchor(f.anchor, nil, f.log)
	if none.Enabled() {
		t.Fatal("an anchor without a key must be disabled")
	}
	if err := none.Write(); err == nil {
		t.Fatal("writing without a key must be an error")
	}
	if _, err := os.Stat(f.anchor); err == nil {
		t.Fatal("no anchor file may be created without a key")
	}
	if none.Status()["enabled"] != false {
		t.Fatalf("status must say disabled: %v", none.Status())
	}
}

// 10. The key never leaves the process: not into the anchor file, not into
// /v1/backends, not into the audit log. Only its bit length may be reported.
func TestAnchorKeyIsNeverExposed(t *testing.T) {
	const key = "s3cr3t-anchor-key-material-32-bytes!"
	t.Setenv(envAnchorKey, key)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	log, err := OpenAuditLog(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = log.Append("run.finished", map[string]any{"run_id": "r1"})
	anchorPath := filepath.Join(dir, "anchors.jsonl")
	anc := NewAnchor(anchorPath, AnchorKeyFromEnv(), log)
	if err := anc.Write(); err != nil {
		t.Fatal(err)
	}
	status := mustJSON(t, anc.Status())
	if strings.Contains(status, key) {
		t.Fatalf("the key leaked into the anchor status: %s", status)
	}
	if want := fmt.Sprintf(`"key_bits":%d`, len(key)*8); !strings.Contains(status, want) {
		t.Fatalf("the key's length may be reported (%s), its value may not: %s", want, status)
	}
	anchorBytes, _ := os.ReadFile(anchorPath)
	if bytes.Contains(anchorBytes, []byte(key)) {
		t.Fatal("the key leaked into the anchor file")
	}
	auditBytes, _ := os.ReadFile(auditPath)
	if bytes.Contains(auditBytes, []byte(key)) {
		t.Fatal("the key leaked into the audit log")
	}
	// Nor may it be served: /v1/backends exposes the anchor status.
	s := testServer(t, "")
	s.anchor = anc
	rec := httptestRecorderGet(t, s, "/v1/backends")
	if strings.Contains(rec, key) {
		t.Fatalf("the key leaked into /v1/backends: %s", rec)
	}
	// Nor in a verification report.
	var out, errOut bytes.Buffer
	runVerify(auditPath, anchorPath, &out, &errOut)
	if strings.Contains(out.String()+errOut.String(), key) {
		t.Fatal("the key leaked into the verify report")
	}
}

// 11. Anchoring is wired into the daemon: the server builds an Anchor bound to
// the live chain head, and the periodic loop writes one without a run happening.
// (A short interval keeps the test fast; the ticker path is the same one the
// boot uses.)
func TestServerAnchorsPeriodically(t *testing.T) {
	setTestAnchorKey(t)
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	s, err := NewServer(Config{
		Workspace:      filepath.Join(dir, "ws"),
		AuditPath:      auditPath,
		TracePath:      filepath.Join(dir, "trace.json"),
		Token:          "t",
		AnchorInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.anchor == nil || !s.anchor.Enabled() {
		t.Fatal("a key is configured, so the server must have an enabled anchor")
	}
	if s.anchor.Path() != filepath.Join(dir, "anchors.jsonl") {
		t.Fatalf("anchor path=%q want it beside the audit log", s.anchor.Path())
	}
	s.StartAnchoring()
	// The first anchor is written immediately, so a fresh log is never
	// unanchored once the daemon is serving.
	_ = s.audit.Append("run.finished", map[string]any{"run_id": "r1"})
	// An anchor is only written when the head *moves* (a duplicate adds no
	// evidence), so the ticker is exercised with real appends in between.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recs, err := ReadAnchors(s.anchor.Path())
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) >= 3 {
			break
		}
		_ = s.audit.Append("run.finished", map[string]any{"run_id": "tick"})
		time.Sleep(10 * time.Millisecond)
	}
	recs, _ := ReadAnchors(s.anchor.Path())
	if len(recs) < 3 {
		t.Fatalf("the periodic anchor did not run, got %d records", len(recs))
	}
	// Shutdown writes a final anchor, so the head at exit is checkable.
	s.Close()
	// Re-read: Close may have appended one more, and the count has to come from
	// the same moment as the check (asserting against a pre-Close read is a race).
	recs, err = ReadAnchors(s.anchor.Path())
	if err != nil {
		t.Fatal(err)
	}
	chk := VerifyAnchoredLog(auditPath, s.anchor.Path(), testAnchorKey)
	if !chk.OK() {
		t.Fatalf("the final anchor must verify: %+v", chk)
	}
	if chk.Verified != len(recs) {
		t.Fatalf("verified=%d want %d (every anchor must authenticate)", chk.Verified, len(recs))
	}
	if chk.Problems != nil {
		t.Fatalf("no problems expected: %v", chk.Problems)
	}
}

// 12. Without a key the daemon still serves — the chain is simply reported as
// unanchored. A missing anchor must not be an outage.
func TestServerWithoutKeyStillServes(t *testing.T) {
	t.Setenv(envAnchorKey, "")
	s := testServer(t, "")
	if s.anchor != nil && s.anchor.Enabled() {
		t.Fatal("no key must mean no anchoring")
	}
	s.StartAnchoring() // must not panic or block
	rec := httptestRecorderGet(t, s, "/v1/backends")
	if !strings.Contains(rec, `"enabled":false`) {
		t.Fatalf("/v1/backends must report the anchor as disabled: %s", rec)
	}
	// -no-anchor leaves the daemon with no Anchor at all.
	dir := t.TempDir()
	s2, err := NewServer(Config{
		Workspace: filepath.Join(dir, "ws"), AuditPath: filepath.Join(dir, "a.jsonl"),
		TracePath: filepath.Join(dir, "t.json"), Token: "t", DisableAnchor: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if s2.anchor != nil {
		t.Fatal("-no-anchor must disable the anchor entirely")
	}
	s2.StartAnchoring()
}

// 13. A truncated log below the newest anchor is tampering, not a short file.
func TestAnchorDetectsTruncationBelowTheAnchor(t *testing.T) {
	f := newAnchorFixture(t, 4)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	// Cut the last two lines: the chain still verifies (it is a valid prefix),
	// but the anchored head is gone.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if err := os.WriteFile(f.audit, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLog(f.audit); err != nil {
		t.Fatalf("test setup: a truncated prefix is still a valid chain, got %v", err)
	}
	chk := VerifyAnchoredLog(f.audit, f.anchor, testAnchorKey)
	if chk.Status != "fail" {
		t.Fatalf("truncation below an anchor must fail: %+v", chk)
	}
}

// 14. A corrupt anchor file fails closed, and an unreadable audit log is a
// failure rather than a warning: "cannot verify" is not "verified".
func TestAnchorFailClosedOnCorruption(t *testing.T) {
	f := newAnchorFixture(t, 2)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.anchor, []byte("{\"not\":\"json\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chk := VerifyAnchoredLog(f.audit, f.anchor, testAnchorKey)
	if chk.Status != "fail" {
		t.Fatalf("a corrupt anchor file must fail: %+v", chk)
	}
	chk = VerifyAnchoredLog(filepath.Join(t.TempDir(), "absent.jsonl"), f.anchor, testAnchorKey)
	if chk.Status != "fail" || !strings.Contains(chk.Note, "cannot verify") {
		t.Fatalf("an unreadable log must fail: %+v", chk)
	}
}

// 15. defaultAnchorPath puts the file where an operator will look, and never
// returns something surprising for an empty audit path.
func TestDefaultAnchorPath(t *testing.T) {
	if got := defaultAnchorPath("/data/audit.jsonl"); got != "/data/anchors.jsonl" {
		t.Fatalf("got %q want /data/anchors.jsonl", got)
	}
	if got := defaultAnchorPath("audit.jsonl"); got != filepath.Join(".", "anchors.jsonl") {
		t.Fatalf("got %q", got)
	}
	if got := defaultAnchorPath(""); got != "" {
		t.Fatalf("an empty audit path must give no anchor path, got %q", got)
	}
}

// 18. The anchor period is settable by flag or environment, and a typo falls back
// to the default rather than disabling anchoring.
func TestAnchorIntervalResolution(t *testing.T) {
	t.Setenv(envAnchorInterval, "45s")
	if got := AnchorIntervalFromEnv(); got != 45*time.Second {
		t.Fatalf("interval=%v want 45s", got)
	}
	// The flag wins over the environment.
	if got := firstPositiveDuration(5*time.Second, AnchorIntervalFromEnv()); got != 5*time.Second {
		t.Fatalf("the flag must win, got %v", got)
	}
	// A zero flag falls through to the environment.
	if got := firstPositiveDuration(0, AnchorIntervalFromEnv()); got != 45*time.Second {
		t.Fatalf("the environment must be used when the flag is unset, got %v", got)
	}
	for _, bad := range []string{"soon", "-5s", "0s", "45"} {
		t.Setenv(envAnchorInterval, bad)
		if got := AnchorIntervalFromEnv(); got != 0 {
			t.Fatalf("%q must be refused, got %v", bad, got)
		}
	}
	t.Setenv(envAnchorInterval, "")
	if got := AnchorIntervalFromEnv(); got != 0 {
		t.Fatalf("unset must mean default, got %v", got)
	}
	// And an unparseable value leaves the Anchor on its built-in default.
	f := newAnchorFixture(t, 1)
	t.Setenv(envAnchorInterval, "nonsense")
	anc := NewAnchor(f.anchor, testAnchorKey, f.log)
	if anc.Interval() != DefaultAnchorInterval {
		t.Fatalf("a bad interval must fall back to %s, got %s", DefaultAnchorInterval, anc.Interval())
	}
}

// 16. The genesis anchor — written immediately at boot, before any line exists —
// must verify against a log that has since grown. It pins "nothing was written
// yet", so it sits *before* line 0 rather than on it. (Found by running the
// daemon rather than by a unit test: an anchor at seq 0 against a 3-line log was
// reported as "not in the log", which made a healthy deployment look forged.)
func TestGenesisAnchorVerifiesAgainstAGrownLog(t *testing.T) {
	f := newAnchorFixtureNoEntries(t)
	// The daemon anchors on start, before the first run is submitted.
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	recs, _ := ReadAnchors(f.anchor)
	if len(recs) != 1 || recs[0].Hash != genesisHash || recs[0].Seq != 0 {
		t.Fatalf("expected a genesis anchor, got %+v", recs)
	}
	// Now the log grows, and a second anchor follows.
	for i := 0; i < 3; i++ {
		_ = f.log.Append("run.finished", map[string]any{"run_id": "r"})
	}
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	chk := VerifyAnchoredLog(f.audit, f.anchor, testAnchorKey)
	if !chk.OK() || len(chk.Problems) != 0 {
		t.Fatalf("a genesis anchor plus a real one must verify: %+v", chk)
	}
	if chk.Verified != 2 || chk.UnanchoredLines != 0 {
		t.Fatalf("unexpected: %+v", chk)
	}
	// The genesis anchor pins nothing on its own — a wholly forged log also
	// starts at GENESIS — which is why the anchor carrying the content is the
	// load-bearing one. Keep only the genesis anchor and the whole log must read
	// as unanchored, not as verified.
	only := f.anchor + ".only"
	if err := os.WriteFile(only, []byte(forgeLine(recs[0])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chk = VerifyAnchoredLog(f.audit, only, testAnchorKey)
	if chk.UnanchoredLines != 3 || chk.Status != "warn" {
		t.Fatalf("a genesis-only anchor must leave the log unanchored: %+v", chk)
	}
	// A genesis anchor claiming a non-zero seq is malformed, not merely
	// unanchoring.
	bad := f.anchor + ".badseq"
	line := strings.Replace(forgeLine(recs[0]), `"seq":0`, `"seq":1`, 1)
	if err := os.WriteFile(bad, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if chk = VerifyAnchoredLog(f.audit, bad, testAnchorKey); chk.Status != "fail" {
		t.Fatalf("a genesis anchor claiming a non-zero seq must fail: %+v", chk)
	}
}

// newAnchorFixtureNoEntries is newAnchorFixture with an empty log — the state
// the daemon is in when it writes its first anchor.
func newAnchorFixtureNoEntries(t *testing.T) *anchorFixture {
	t.Helper()
	dir := t.TempDir()
	f := &anchorFixture{
		audit:  filepath.Join(dir, "audit.jsonl"),
		anchor: filepath.Join(dir, "anchors.jsonl"),
	}
	log, err := OpenAuditLog(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	f.log = log
	f.anc = NewAnchor(f.anchor, testAnchorKey, log)
	return f
}

// forgeLine re-serialises an anchor record (so one field can be hand-edited).
func forgeLine(r AnchorRecord) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// 17. The mismatch banner must appear once. (Also found by running the daemon:
// the report's note and the CLI's prefix both said "ANCHOR MISMATCH".)
func TestVerifyAnchorBannerIsNotDuplicated(t *testing.T) {
	f := newAnchorFixture(t, 2)
	if err := f.anc.Write(); err != nil {
		t.Fatal(err)
	}
	// Forge the whole log, so the anchor check fails with real content.
	if err := os.WriteFile(f.audit, forgeChain(t, []map[string]any{{"event": "run.finished", "status": "forged"}}), 0o600); err != nil {
		t.Fatal(err)
	}
	setTestAnchorKey(t)
	var out, errOut bytes.Buffer
	if code := runVerify(f.audit, f.anchor, &out, &errOut); code != 1 {
		t.Fatalf("exit=%d want 1", code)
	}
	if n := strings.Count(errOut.String(), "ANCHOR MISMATCH"); n != 1 {
		t.Fatalf("the banner must appear exactly once, got %d:\n%s", n, errOut.String())
	}
}
