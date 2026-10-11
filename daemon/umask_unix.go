//go:build !windows

package main

import "syscall"

// umask wraps syscall.Umask (not available on Windows; daemon is unix-only).
func umask(mask int) int { return syscall.Umask(mask) }
