package main

import (
	"context"
	"sync"
	"sync/atomic"
)

// KillSwitch is a global breaker: once engaged, no new run may start and
// all in-flight runs are cancelled. It latches until explicitly released,
// so a panicking agent loop cannot silently resume.
type KillSwitch struct {
	engaged atomic.Bool
	reason  atomic.Value // string
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
	runs    *Store
}

func NewKillSwitch(runs *Store) *KillSwitch {
	return &KillSwitch{cancels: make(map[string]context.CancelFunc), runs: runs}
}

// Engage latches the switch and cancels every tracked run.
func (k *KillSwitch) Engage(reason string) {
	k.reason.Store(reason)
	if k.engaged.Swap(true) {
		return // already latched; keep original reason semantics simple
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for id, cancel := range k.cancels {
		cancel()
		k.runs.setStatus(id, StatusKilled)
		k.runs.hub.Broadcast(newEvent("run.killed", id, map[string]any{"reason": reason}))
	}
	k.runs.hub.Broadcast(newEvent("killswitch", "", map[string]any{"engaged": true, "reason": reason}))
}

// Release unlatches the switch so new runs may be submitted again.
func (k *KillSwitch) Release() {
	k.engaged.Store(false)
	k.runs.hub.Broadcast(newEvent("killswitch", "", map[string]any{"engaged": false}))
}

// Engaged reports whether the switch is currently latched.
func (k *KillSwitch) Engaged() bool { return k.engaged.Load() }

// Reason returns the last engage reason.
func (k *KillSwitch) Reason() string {
	v := k.reason.Load()
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// Track registers a run's cancel func; returns false if the switch is
// latched (caller must refuse to start the run).
func (k *KillSwitch) Track(id string, cancel context.CancelFunc) bool {
	if k.Engaged() {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.Engaged() {
		return false
	}
	k.cancels[id] = cancel
	return true
}

// Untrack forgets a finished run.
func (k *KillSwitch) Untrack(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.cancels, id)
}

// KillRun cancels one in-flight run. Returns false if unknown/finished.
func (k *KillSwitch) KillRun(id string) bool {
	k.mu.Lock()
	cancel, ok := k.cancels[id]
	k.mu.Unlock()
	if !ok {
		return false
	}
	cancel()
	return true
}
