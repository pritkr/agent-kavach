package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config wires the daemon together.
type Config struct {
	SocketPath     string
	TokenPath      string
	Workspace      string
	AuditPath      string
	TracePath      string
	Workers        int
	DefaultTimeout int
	Token          string
	// PolicyPath is the policy.yaml manifest loaded at boot ("" = built-in
	// defaults). Policy, when non-nil, overrides PolicyPath (tests).
	PolicyPath string
	Policy     *Policy
	// AnchorPath is the external anchor file (v3). Empty = beside the audit log.
	AnchorPath string
	// AnchorInterval overrides the default anchor period (0 = default).
	AnchorInterval time.Duration
	// DisableAnchor turns the periodic anchor off; -verify still checks an
	// existing anchor file and reports the unanchored window.
	DisableAnchor bool
	// Backend pins the sandbox backend ("" = the policy's value).
	Backend string
}

// Server is the Unix-socket HTTP API + job queue + workers.
type Server struct {
	cfg      Config
	mux      *http.ServeMux
	ln       net.Listener
	store    *Store
	ks       *KillSwitch
	audit    *AuditLog
	met      *Metrics
	policy   *Policy
	vault    *Vault
	backends *BackendRegistry
	anchor   *Anchor
	// hardening is the boot-time report of what the local executor enforces.
	hardening HardeningReport
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.DefaultTimeout <= 0 {
		cfg.DefaultTimeout = 120
	}
	pol := cfg.Policy
	if pol == nil {
		var err error
		pol, err = LoadPolicy(cfg.PolicyPath)
		if err != nil {
			return nil, err
		}
	}
	if cfg.Workspace == "" {
		cfg.Workspace = pol.Workspace
	}
	if err := os.MkdirAll(cfg.Workspace, 0o700); err != nil {
		return nil, err
	}
	vault := NewVault(pol)
	// The log scrubs secrets itself, so no call site can forget to.
	audit, err := OpenAuditLogRedacted(cfg.AuditPath, vault.SecretsSnapshot)
	if err != nil {
		return nil, err
	}
	pinned := firstNonEmpty(cfg.Backend, pol.Backend)
	s := &Server{
		cfg:       cfg,
		mux:       http.NewServeMux(),
		store:     NewStore(1024),
		met:       NewMetrics(),
		policy:    pol,
		vault:     vault,
		backends:  NewBackendRegistry(pinned),
		hardening: SandboxHardening(),
	}
	s.ks = NewKillSwitch(s.store)
	s.audit = audit
	if !cfg.DisableAnchor {
		s.anchor = NewAnchor(firstNonEmpty(cfg.AnchorPath, defaultAnchorPath(cfg.AuditPath)), AnchorKeyFromEnv(), audit)
		if cfg.AnchorInterval > 0 {
			s.anchor.SetInterval(cfg.AnchorInterval)
		}
	}
	s.routes()
	for i := 0; i < cfg.Workers; i++ {
		go s.worker()
	}
	return s, nil
}

// StartAnchoring begins the periodic external anchor. It is a no-op when no key
// is configured — the daemon then logs (once) that the audit chain is unanchored
// and carries on, because refusing to boot would be worse than a loudly
// unanchored chain.
func (s *Server) StartAnchoring() {
	if s.anchor == nil || !s.anchor.Enabled() {
		logHardeningWarn("anchor-off", fmt.Sprintf("no external audit anchor: set %s (>=%d bytes) to bind the audit chain head to an HMAC. -verify will report the log as UNANCHORED until then", envAnchorKey, MinAnchorKeyBytes))
		return
	}
	log.Printf("audit anchor: %s every %s (key from %s, %d bits, never logged)", s.anchor.Path(), s.anchor.Interval(), envAnchorKey, len(AnchorKeyFromEnv())*8)
	s.anchor.Start()
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/v1/runs", s.handleRuns)       // POST submit, GET list
	s.mux.HandleFunc("/v1/runs/", s.handleRunDetail) // GET one, POST .../kill
	s.mux.HandleFunc("/v1/killswitch", s.handleKillSwitch)
	s.mux.HandleFunc("/v1/events", s.handleEvents)
	s.mux.HandleFunc("/v1/tool-calls", s.handleToolCalls)
	s.mux.HandleFunc("/v1/audit", s.handleAudit)
	s.mux.HandleFunc("/v1/policy", s.handlePolicy)
	s.mux.HandleFunc("/v1/backends", s.handleBackends) // which executors exist, and which is live
	s.mux.HandleFunc("/metrics", s.handleMetrics)
}

// ActiveBackendName is the backend a run would use right now, or the reason one
// is not usable. Used in the boot log.
func (s *Server) ActiveBackendName() string {
	b, err := s.backends.Select()
	if err != nil {
		return "none (" + err.Error() + ")"
	}
	return b.Name()
}

// Serve binds the Unix socket with 0600 perms and serves the API.
func (s *Server) Serve() error {
	if err := os.MkdirAll(filepath.Dir(s.cfg.SocketPath), 0o700); err != nil {
		return err
	}
	_ = os.Remove(s.cfg.SocketPath) // stale socket from unclean shutdown
	// Restrictive umask so the socket is born 0600-ish, then chmod explicitly.
	old := umask(0o177)
	ln, err := net.Listen("unix", s.cfg.SocketPath)
	umask(old)
	if err != nil {
		return err
	}
	_ = os.Chmod(s.cfg.SocketPath, 0o600)
	s.ln = ln
	return http.Serve(ln, bearerAuth(s.cfg.Token, s.mux))
}

// Close stops the listener and writes a final audit anchor, so the chain head at
// shutdown is the last thing a verifier can check.
func (s *Server) Close() {
	if s.anchor != nil {
		s.anchor.Stop()
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

// EngageKillSwitch latches the breaker (used by shutdown + API).
func (s *Server) EngageKillSwitch(reason string) {
	s.ks.Engage(reason)
	s.met.IncKillSwitch()
	s.auditEvent("killswitch.engaged", map[string]any{"reason": reason})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// writeToolErr emits a structured MCP-style error envelope so gateway and
// daemon rejections share the same {code, message} shape.
func writeToolErr(w http.ResponseWriter, httpCode int, code, msg, tool string) {
	writeJSON(w, httpCode, map[string]any{
		"ok": false, "tool": tool,
		"error": map[string]string{"code": code, "message": msg},
	})
}

// auditEvent appends to the tamper-evident log. Callers pass raw fields; the
// log scrubs secret values on the way to disk, so only [REDACTED] is ever
// written and no call site has to remember to redact.
func (s *Server) auditEvent(event string, fields map[string]any) {
	_ = s.audit.Append(event, fields)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"ok": true, "service": "agent-kavach",
		"docker": DockerAvailable(), "killswitch": s.ks.Engaged(),
		"backend": s.backends.Active(),
		"time":    time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// handleBackends answers "what can actually run here, and what is in force".
//
// It serves evidence rather than claims: each backend's availability with the
// reason when it is missing, the policy pin, what a run would resolve to (or the
// structured reason it cannot), the local executor's kernel controls, and the
// anchor's health. Nothing here is a secret — no key, no key material, only the
// key's bit length.
func (s *Server) handleBackends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method not allowed")
		return
	}
	active, selErr := s.backends.Select()
	body := map[string]any{
		"pinned":    s.backends.Pinned(),
		"active":    s.backends.Active(),
		"backends":  s.backends.InspectAll(),
		"hardening": s.hardening,
		"anchor":    s.anchor.Status(),
	}
	if selErr != nil {
		var be *BackendUnavailableError
		if errors.As(selErr, &be) {
			body["unavailable"] = be
		} else {
			body["unavailable"] = map[string]string{"backend": BackendAuto, "reason": selErr.Error()}
		}
	} else {
		body["resolved_to"] = active.Name()
		body["isolation"] = active.Inspect().Isolation
	}
	writeJSON(w, 200, body)
}

// --- runs ---

type submitReq struct {
	Command    []string `json:"command"`
	Image      string   `json:"image,omitempty"`
	TimeoutSec int      `json:"timeout_sec,omitempty"`
	// Tool optionally binds the run to a policy tool: the tool must be known
	// and allowed, the timeout defaults to (and is capped by) the per-tool
	// policy timeout, and the child receives the tool's vault env allowlist.
	Tool string `json:"tool,omitempty"`
}

func validateCommand(cmd []string) error {
	if len(cmd) == 0 {
		return fmt.Errorf("command is empty")
	}
	if len(cmd) > 64 {
		return fmt.Errorf("command has too many args (max 64)")
	}
	for _, a := range cmd {
		if len(a) > 8192 {
			return fmt.Errorf("argument too long (max 8192 bytes)")
		}
		if strings.ContainsRune(a, '\x00') {
			return fmt.Errorf("argument contains NUL byte")
		}
	}
	return nil
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"runs": s.store.ListRedacted(s.vault.SecretsSnapshot())})
	case http.MethodPost:
		var req submitReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeErr(w, 400, "invalid JSON: "+err.Error())
			return
		}
		if err := validateCommand(req.Command); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if req.Tool != "" {
			if !IsKnownTool(req.Tool) {
				writeToolErr(w, 400, "unknown_tool", fmt.Sprintf("unknown tool: %q", req.Tool), req.Tool)
				return
			}
			if !s.policy.Allowed(req.Tool) {
				writeToolErr(w, 403, "tool_denied", fmt.Sprintf("tool %q is denied by policy", req.Tool), req.Tool)
				return
			}
			eff, err := s.policy.ResolveTimeout(req.Tool, req.TimeoutSec)
			if err != nil {
				writeToolErr(w, 400, "invalid_args", err.Error(), req.Tool)
				return
			}
			req.TimeoutSec = eff
		} else {
			if req.TimeoutSec <= 0 {
				req.TimeoutSec = s.cfg.DefaultTimeout
			}
			if req.TimeoutSec > 1800 {
				writeErr(w, 400, "timeout_sec max is 1800")
				return
			}
		}
		if s.ks.Engaged() {
			writeErr(w, 409, "kill-switch engaged: "+s.ks.Reason())
			return
		}
		tr := NewTracer()
		run := &Run{
			ID: newID(), Command: req.Command, Image: req.Image, Tool: req.Tool,
			Status: StatusQueued, TraceID: tr.TraceID(),
			QueuedAt: time.Now().UTC(), TimeoutSec: req.TimeoutSec,
		}
		s.met.IncSubmitted()
		s.auditEvent("run.submitted", map[string]any{"run_id": run.ID, "command": req.Command, "tool": req.Tool})
		// Snapshot the reply before Enqueue: the store hands this very *Run to a
		// worker goroutine, which mutates it (status, spans) the moment it is
		// picked up. Reading run.* after Enqueue would be a data race.
		reply := map[string]any{"id": run.ID, "trace_id": run.TraceID, "status": run.Status}
		s.store.Enqueue(run, s.vault.SecretsSnapshot())
		writeJSON(w, 202, reply)
	default:
		writeErr(w, 405, "method not allowed")
	}
}

func (s *Server) handleRunDetail(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/runs/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		writeErr(w, 404, "not found")
		return
	}
	if len(parts) == 2 && parts[1] == "kill" {
		if r.Method != http.MethodPost {
			writeErr(w, 405, "method not allowed")
			return
		}
		run, ok := s.store.Get(id)
		if !ok {
			writeErr(w, 404, "unknown run")
			return
		}
		if run.Status != StatusRunning && run.Status != StatusQueued {
			writeErr(w, 409, "run already finished: "+string(run.Status))
			return
		}
		if !s.ks.KillRun(id) {
			// Queued but not started: mark killed directly.
			s.store.setStatus(id, StatusKilled)
		}
		s.met.IncKilled()
		s.auditEvent("run.killed", map[string]any{"run_id": id})
		s.store.hub.Broadcast(newEvent("run.killed", id, map[string]any{"by": "api"}))
		writeJSON(w, 200, map[string]any{"id": id, "killed": true})
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method not allowed")
		return
	}
	run, ok := s.store.Get(id)
	if !ok {
		writeErr(w, 404, "unknown run")
		return
	}
	writeJSON(w, 200, run.Redacted(s.vault.SecretsSnapshot()))
}

// --- killswitch ---

func (s *Server) handleKillSwitch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"engaged": s.ks.Engaged(), "reason": s.ks.Reason()})
	case http.MethodPost:
		var req struct {
			Engaged bool   `json:"engaged"`
			Reason  string `json:"reason,omitempty"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeErr(w, 400, "invalid JSON: "+err.Error())
			return
		}
		if req.Engaged {
			reason := req.Reason
			if reason == "" {
				reason = "manual"
			}
			s.EngageKillSwitch(reason)
		} else {
			s.ks.Release()
			s.auditEvent("killswitch.released", nil)
		}
		writeJSON(w, 200, map[string]any{"engaged": s.ks.Engaged(), "reason": s.ks.Reason()})
	default:
		writeErr(w, 405, "method not allowed")
	}
}

// --- SSE event stream ---

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	filter := r.URL.Query().Get("run_id")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)
	_, _ = fmt.Fprintf(w, ": connected\n\n")
	fl.Flush()

	ch, unsub := s.store.hub.Subscribe(64)
	defer unsub()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = fmt.Fprintf(w, ": ping\n\n")
			fl.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if filter != "" && ev.RunID != filter && ev.Type != "killswitch" {
				continue
			}
			data, _ := json.Marshal(ev)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
			fl.Flush()
		}
	}
}

// --- tool call accounting (reported by the MCP server) ---

func (s *Server) handleToolCalls(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed")
		return
	}
	var req struct {
		Tool string `json:"tool"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil || req.Tool == "" {
		writeErr(w, 400, "need {\"tool\": \"<name>\"}")
		return
	}
	// Policy enforcement at the daemon edge: unknown tools are rejected with
	// a structured error, denied tools with 403 — mirroring the MCP gateway.
	if !IsKnownTool(req.Tool) {
		writeToolErr(w, 400, "unknown_tool", fmt.Sprintf("unknown tool: %q", req.Tool), req.Tool)
		return
	}
	if !s.policy.Allowed(req.Tool) {
		writeToolErr(w, 403, "tool_denied", fmt.Sprintf("tool %q is denied by policy", req.Tool), req.Tool)
		return
	}
	s.met.IncToolCall(req.Tool)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// --- policy view (what the daemon enforces; secrets never included) ---

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method not allowed")
		return
	}
	tools := map[string]any{}
	for _, name := range KnownTools {
		tp := s.policy.Tools[name]
		tools[name] = map[string]any{
			"allow": tp.Allow, "timeout_sec": s.policy.TimeoutFor(name),
		}
	}
	writeJSON(w, 200, map[string]any{
		"workspace":           s.policy.Workspace,
		"network_allowlist":   s.policy.NetworkAllowlist,
		"default_timeout_sec": s.policy.DefaultTimeout,
		"backend":             s.backends.Pinned(),
		"tools":               tools,
	})
}

// --- audit tail (replay view) ---

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method not allowed")
		return
	}
	entries, err := s.audit.ReadAll()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"entries": entries, "count": len(entries)})
}

// --- metrics ---

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(s.met.Render()))
}

// --- worker ---

func (s *Server) worker() {
	for id := range s.store.q {
		s.runJob(id)
	}
}

func (s *Server) runJob(id string) {
	run, ok := s.store.Get(id)
	if !ok {
		return
	}
	if s.ks.Engaged() {
		s.store.setStatus(id, StatusKilled)
		s.store.hub.Broadcast(newEvent("run.killed", id, map[string]any{"reason": s.ks.Reason()}))
		s.auditEvent("run.killed", map[string]any{"run_id": id, "reason": "killswitch-engaged-at-start"})
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !s.ks.Track(id, cancel) {
		s.store.setStatus(id, StatusKilled)
		return
	}
	defer s.ks.Untrack(id)

	secrets := s.vault.SecretsSnapshot()
	tr := NewTracer()
	// Re-bind: the exported trace id should match the run's trace id.
	tr.trace = run.TraceID
	// A submitted command may itself carry a credential, so the command echoed
	// into spans and events is scrubbed with the same vault snapshot.
	cmdStr := RedactText(strings.Join(run.Command, " "), secrets)
	root := tr.Start("run", "", map[string]any{"run_id": id, "command": cmdStr})
	s.store.setStatus(id, StatusRunning)
	s.store.hub.Broadcast(newEvent("run.started", id, map[string]any{"command": RedactStrings(run.Command, secrets)}))
	s.auditEvent("run.started", map[string]any{"run_id": id})

	execSpan := tr.Start("sandbox.exec", root.SpanID, map[string]any{"image": run.Image, "timeout_sec": run.TimeoutSec, "backend": s.backends.Active()})
	res := s.execute(ctx, run)
	tr.End(execSpan, statusFor(res))

	durSec := 0.0
	if fresh, ok := s.store.Get(id); ok && !fresh.StartedAt.IsZero() {
		durSec = time.Since(fresh.StartedAt).Seconds()
	}
	cost := EstimateCost(res.Sandbox, durSec, len(res.Output))
	status := StatusDone
	code := "OK"
	if res.Killed {
		status = StatusKilled
		code = "ERROR"
		s.met.IncKilled()
	} else if res.ExitCode != 0 {
		status = StatusFailed
		code = "ERROR"
	}
	tr.End(root, code)
	// Redacted copy is what gets stored, served and replayed: the trajectory
	// (spans on the run record) is a log and must not hold secret values.
	spans := RedactSpans(tr.Export(), secrets)
	s.store.finish(id, status, res.ExitCode, res.Output, res.ErrMsg, res.Sandbox, cost, spans)
	s.met.IncCompleted(string(status))
	if fin, ok := s.store.Get(id); ok {
		s.met.ObserveDuration(fin.DurationMs)
	}
	_ = DumpTraceFileRedacted(s.cfg.TracePath, id, spans, secrets)
	s.auditEvent("run.finished", map[string]any{
		"run_id": id, "status": string(status), "exit_code": res.ExitCode,
		"sandbox": res.Sandbox, "cost_usd": cost, "hardening": res.Hardening,
	})
	s.store.hub.Broadcast(newEvent("run.finished", id, map[string]any{"status": string(status), "exit_code": res.ExitCode, "sandbox": res.Sandbox}))
}

// execute runs a job through the backend registry. The v2 executor picked docker
// or local with an if/else; v3 asks the registry, so a pinned backend that cannot
// run fails the run with a structured reason instead of quietly running it
// somewhere weaker.
func (s *Server) execute(ctx context.Context, run *Run) ExecResult {
	backend, err := s.backends.Select()
	if err != nil {
		s.auditEvent("run.backend_unavailable", map[string]any{
			"run_id": run.ID, "pinned": s.backends.Pinned(), "reason": err.Error(),
		})
		// 125 is docker's own "cannot run the container" code; reusing it keeps
		// the failure legible to anyone reading the run's exit status. The run
		// reports the backend it *asked for*, never one that did the work.
		requested := "none"
		var be *BackendUnavailableError
		if errors.As(err, &be) {
			requested = be.Backend
		}
		return ExecResult{
			Sandbox:   requested,
			ExitCode:  125,
			ErrMsg:    err.Error(),
			Hardening: "none",
		}
	}
	out := backend.Run(ctx, RunRequest{
		Command:   run.Command,
		Image:     run.Image,
		Workspace: s.cfg.Workspace,
		Timeout:   time.Duration(run.TimeoutSec) * time.Second,
		Name:      "kavach-" + run.ID[:12],
		Env:       buildEnv(run.Tool, s.vault),
	})
	return redactOutcome(ExecResult{
		Output:    out.Output,
		ExitCode:  out.ExitCode,
		Killed:    out.Killed,
		ErrMsg:    out.ErrMsg,
		Sandbox:   out.Backend,
		Hardening: out.Hardening,
	}, s.vault)
}

func statusFor(res ExecResult) string {
	if res.Killed || res.ExitCode != 0 {
		return "ERROR"
	}
	return "OK"
}
