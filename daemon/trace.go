package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// trace.go — OpenTelemetry-style trace JSON.
//
// We emit OTel-compatible field names (traceId, spanId, parentSpanId,
// name, startTimeUnixNano, endTimeUnixNano, attributes, status) so the
// JSON can be forwarded to any OTel collector or our Langfuse stub
// without transformation.

type SpanStatus struct {
	Code string `json:"code"` // OK | ERROR | UNSET
}

// Span is a single timed operation inside a run.
type Span struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	StartTimeUnixNano int64          `json:"startTimeUnixNano"`
	EndTimeUnixNano   int64          `json:"endTimeUnixNano,omitempty"`
	Attributes        map[string]any `json:"attributes,omitempty"`
	Status            SpanStatus     `json:"status"`
}

// SpanExport is the JSON shape stored on a Run.
type SpanExport = Span

// Tracer owns one trace (one run) and its span tree.
type Tracer struct {
	mu     sync.Mutex
	trace  string
	spans  []*Span
	active map[string]*Span
}

func NewTracer() *Tracer {
	return &Tracer{trace: hexID(), active: make(map[string]*Span)}
}

func hexID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Start begins a child span of parent (empty parent = root).
func (t *Tracer) Start(name, parent string, attrs map[string]any) *Span {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := &Span{
		TraceID:           t.trace,
		SpanID:            hexID(),
		ParentSpanID:      parent,
		Name:              name,
		StartTimeUnixNano: time.Now().UnixNano(),
		Attributes:        attrs,
		Status:            SpanStatus{Code: "UNSET"},
	}
	t.spans = append(t.spans, s)
	t.active[s.SpanID] = s
	return s
}

// End closes a span with a status code.
func (t *Tracer) End(s *Span, code string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s.EndTimeUnixNano = time.Now().UnixNano()
	s.Status.Code = code
	delete(t.active, s.SpanID)
}

// TraceID returns the trace identifier.
func (t *Tracer) TraceID() string { return t.trace }

// Export returns a snapshot copy of all spans.
func (t *Tracer) Export() []Span {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Span, len(t.spans))
	for i, s := range t.spans {
		out[i] = *s
	}
	return out
}

// DurationMs returns whole-millisecond duration of a span (0 if open).
func (s *Span) DurationMs() int64 {
	if s.EndTimeUnixNano <= s.StartTimeUnixNano {
		return 0
	}
	return (s.EndTimeUnixNano - s.StartTimeUnixNano) / 1e6
}

// RedactSpans returns a copy of spans with every secret value in attributes
// (and, defensively, in names) replaced by [REDACTED]. A nil/empty secrets
// list returns the spans unchanged.
func RedactSpans(spans []Span, secrets []string) []Span {
	nonempty := false
	for _, s := range secrets {
		if s != "" {
			nonempty = true
			break
		}
	}
	if !nonempty {
		return spans
	}
	out := make([]Span, len(spans))
	for i, s := range spans {
		s.Attributes = RedactMap(s.Attributes, secrets)
		s.Name = RedactText(s.Name, secrets)
		out[i] = s
	}
	return out
}

// DumpTraceFile appends one trace document to path (0600).
func DumpTraceFile(path, runID string, spans []Span) error {
	return DumpTraceFileRedacted(path, runID, spans, nil)
}

// DumpTraceFileRedacted appends one trace document to path (0600) after
// masking every secret value in span attributes. Secrets are injected at
// exec time and must never land in the trajectory ledger: even if a command
// echoes its own environment, only [REDACTED] reaches disk.
func DumpTraceFileRedacted(path, runID string, spans []Span, secrets []string) error {
	doc := map[string]any{"run_id": runID, "dumped_at": time.Now().UTC().Format(time.RFC3339Nano), "spans": RedactSpans(spans, secrets)}
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
