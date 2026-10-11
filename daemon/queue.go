package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// RunStatus is the lifecycle state of a sandboxed run.
type RunStatus string

const (
	StatusQueued  RunStatus = "queued"
	StatusRunning RunStatus = "running"
	StatusDone    RunStatus = "done"
	StatusFailed  RunStatus = "failed"
	StatusKilled  RunStatus = "killed"
)

// Run is a single sandboxed agent command execution.
type Run struct {
	ID         string       `json:"id"`
	Command    []string     `json:"command"`
	Image      string       `json:"image,omitempty"`
	Tool       string       `json:"tool,omitempty"` // policy tool binding (vault env + timeout)
	Status     RunStatus    `json:"status"`
	ExitCode   int          `json:"exit_code"`
	Output     string       `json:"output,omitempty"`
	Error      string       `json:"error,omitempty"`
	TraceID    string       `json:"trace_id"`
	QueuedAt   time.Time    `json:"queued_at"`
	StartedAt  time.Time    `json:"started_at,omitempty"`
	EndedAt    time.Time    `json:"ended_at,omitempty"`
	DurationMs int64        `json:"duration_ms"`
	CostUSD    float64      `json:"cost_usd"`
	TimeoutSec int          `json:"timeout_sec"`
	Sandbox    string       `json:"sandbox"` // "docker" | "local"
	Spans      []SpanExport `json:"spans,omitempty"`
}

// Redacted returns a copy safe to serialize or stream: every field that could
// echo a credential (argv, image, output, error, span attributes) is masked.
// The stored run keeps its raw command so it can still be executed.
func (r *Run) Redacted(secrets []string) *Run {
	if r == nil || len(secrets) == 0 {
		return r
	}
	cp := *r
	cp.Command = RedactStrings(r.Command, secrets)
	cp.Image = RedactText(r.Image, secrets)
	cp.Output = RedactText(r.Output, secrets)
	cp.Error = RedactText(r.Error, secrets)
	cp.Spans = RedactSpans(r.Spans, secrets)
	return &cp
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Event is broadcast to SSE subscribers on every state transition.
type Event struct {
	Type  string `json:"type"` // run.queued | run.started | run.log | run.finished | run.killed | killswitch
	RunID string `json:"run_id,omitempty"`
	Data  any    `json:"data,omitempty"`
	At    string `json:"at"`
}

func newEvent(typ, runID string, data any) Event {
	return Event{Type: typ, RunID: runID, Data: data, At: time.Now().UTC().Format(time.RFC3339Nano)}
}

// Hub is a tiny SSE fan-out bus. Broadcasts never block the sender.
type Hub struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func NewHub() *Hub { return &Hub{subs: make(map[chan Event]struct{})} }

func (h *Hub) Subscribe(buf int) (chan Event, func()) {
	ch := make(chan Event, buf)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		close(ch)
		h.mu.Unlock()
	}
}

func (h *Hub) Broadcast(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default: // slow consumer: drop, never block the runner
		}
	}
}

// Store is the in-memory job registry + queue.
type Store struct {
	mu   sync.Mutex
	runs map[string]*Run
	q    chan string
	hub  *Hub
}

func NewStore(queueDepth int) *Store {
	return &Store{runs: make(map[string]*Run), q: make(chan string, queueDepth), hub: NewHub()}
}

// Enqueue registers a run and hands it to the worker pool. The optional
// secrets argument scrubs the run.queued SSE payload: telemetry is a log too,
// so an argv that embeds a credential must be masked on the way out.
func (s *Store) Enqueue(r *Run, secrets ...[]string) {
	var scrub []string
	if len(secrets) > 0 {
		scrub = secrets[0]
	}
	s.mu.Lock()
	s.runs[r.ID] = r
	s.mu.Unlock()
	s.q <- r.ID
	s.hub.Broadcast(newEvent("run.queued", r.ID, map[string]any{"command": RedactStrings(r.Command, scrub)}))
}

func (s *Store) Get(id string) (*Run, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok {
		return nil, false
	}
	cp := *r
	return &cp, true
}

func (s *Store) List() []Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Run, 0, len(s.runs))
	for _, r := range s.runs {
		out = append(out, *r)
	}
	return out
}

// ListRedacted is List with credentials masked, for the HTTP read path.
func (s *Store) ListRedacted(secrets []string) []*Run {
	runs := s.List()
	out := make([]*Run, len(runs))
	for i := range runs {
		out[i] = runs[i].Redacted(secrets)
	}
	return out
}

func (s *Store) update(id string, fn func(*Run)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.runs[id]; ok {
		fn(r)
	}
}

func (s *Store) setStatus(id string, st RunStatus) {
	s.update(id, func(r *Run) {
		r.Status = st
		now := time.Now().UTC()
		switch st {
		case StatusRunning:
			r.StartedAt = now
		case StatusDone, StatusFailed, StatusKilled:
			r.EndedAt = now
			if !r.StartedAt.IsZero() {
				r.DurationMs = now.Sub(r.StartedAt).Milliseconds()
			}
		default:
		}
	})
}

func (s *Store) finish(id string, st RunStatus, exitCode int, output, errMsg, sandbox string, cost float64, spans []SpanExport) {
	s.update(id, func(r *Run) {
		r.Status = st
		r.ExitCode = exitCode
		r.Output = output
		r.Error = errMsg
		r.Sandbox = sandbox
		r.CostUSD = cost
		r.Spans = spans
		now := time.Now().UTC()
		r.EndedAt = now
		if !r.StartedAt.IsZero() {
			r.DurationMs = now.Sub(r.StartedAt).Milliseconds()
		}
	})
}

var errQueueClosed = fmt.Errorf("queue closed")
