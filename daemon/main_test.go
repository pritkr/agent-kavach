package main

// main_test.go — the test binary behaves like the daemon in the executor's
// internal helper modes.
//
// The v3 local executor re-execs *this binary* to install no_new_privs, the
// seccomp filter and the cgroup caps in the child before it execs the payload,
// and the seccomp capability probe forks it the same way. Under `go test` the
// entry point is the generated test main, not the daemon's main(), so without
// this the re-exec would re-run the whole suite instead of applying a filter.
//
// It is platform-independent on purpose: the child half of the re-exec — the
// code that ends in execve(2), where a bare command name is not resolved against
// PATH — is the part that decides whether a hardened run works at all. A
// macOS dev box never takes the hardened path, so covering it only under
// `//go:build linux` would mean the executor's most fragile line is tested on
// exactly one platform, by one CI job. Dispatching here lets the portable suite
// exercise the real helper too. The `go test` bookkeeping flags (-test.run,
// -test.paniconexit0, …) are not one of the markers, so the ordinary test path
// is untouched.

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if code, handled := internalMode(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}
