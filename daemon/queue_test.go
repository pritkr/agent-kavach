package main

import (
	"testing"
	"time"
)

func TestStoreEnqueueGetList(t *testing.T) {
	s := NewStore(16)
	r := &Run{ID: "abc", Command: []string{"echo", "hi"}, Status: StatusQueued}
	s.Enqueue(r)
	<-s.q // worker would consume; drain for test isolation

	got, ok := s.Get("abc")
	if !ok {
		t.Fatal("Get missed enqueued run")
	}
	if got.ID != "abc" || got.Status != StatusQueued {
		t.Fatalf("unexpected run: %+v", got)
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatal("Get should miss unknown id")
	}
	if len(s.List()) != 1 {
		t.Fatalf("List len = %d, want 1", len(s.List()))
	}
}

func TestStoreStatusLifecycle(t *testing.T) {
	s := NewStore(16)
	s.runs["x"] = &Run{ID: "x", Status: StatusQueued}
	s.setStatus("x", StatusRunning)
	got, _ := s.Get("x")
	if got.Status != StatusRunning || got.StartedAt.IsZero() {
		t.Fatalf("bad running transition: %+v", got)
	}
	time.Sleep(2 * time.Millisecond)
	s.setStatus("x", StatusDone)
	got, _ = s.Get("x")
	if got.Status != StatusDone || got.EndedAt.IsZero() || got.DurationMs < 0 {
		t.Fatalf("bad done transition: %+v", got)
	}
}

func TestHubBroadcastAndDrop(t *testing.T) {
	h := NewHub()
	ch, unsub := h.Subscribe(2)
	defer unsub()
	h.Broadcast(newEvent("run.queued", "r1", nil))
	select {
	case ev := <-ch:
		if ev.RunID != "r1" || ev.Type != "run.queued" {
			t.Fatalf("bad event: %+v", ev)
		}
		if ev.At == "" {
			t.Fatal("event missing timestamp")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event received")
	}
	// Slow consumer with full buffer must not block the broadcaster.
	ch2, unsub2 := h.Subscribe(0)
	_ = ch2
	defer unsub2()
	done := make(chan struct{})
	go func() { h.Broadcast(newEvent("x", "y", nil)); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("broadcast blocked on slow consumer")
	}
}
