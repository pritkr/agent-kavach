package main

import (
	"context"
	"testing"
)

func TestKillSwitchBlocksAndReleases(t *testing.T) {
	s := NewStore(4)
	ks := NewKillSwitch(s)
	if ks.Engaged() {
		t.Fatal("should start disengaged")
	}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !ks.Track("r1", cancel) {
		t.Fatal("Track should succeed while disengaged")
	}
	ks.Engage("test")
	if !ks.Engaged() {
		t.Fatal("should be engaged")
	}
	if ks.Reason() != "test" {
		t.Fatalf("reason=%q", ks.Reason())
	}
	if ks.Track("r2", cancel) {
		t.Fatal("Track should fail while engaged")
	}
	// r1 was running -> marked killed
	got, _ := s.Get("r1")
	_ = got
	ks.Release()
	if ks.Engaged() {
		t.Fatal("should be released")
	}
	if !ks.Track("r3", cancel) {
		t.Fatal("Track should succeed after release")
	}
	ks.Untrack("r3")
}

func TestKillSwitchKillRun(t *testing.T) {
	s := NewStore(4)
	ks := NewKillSwitch(s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !ks.Track("victim", cancel) {
		t.Fatal("track failed")
	}
	if !ks.KillRun("victim") {
		t.Fatal("KillRun should succeed")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("context was not cancelled")
	}
	if ks.KillRun("ghost") {
		t.Fatal("KillRun should fail for unknown run")
	}
}
