package main

import (
	"os"
	"strings"
)

// vault.go — credential vault (v2).
//
// There is deliberately no network secret store here (non-goal for v2): the
// "vault" is the policy.yaml env allowlist plus process-env injection at exec
// time. Each tool declares the exact env names it may receive; web-fetch and
// eval-run declare none, so untrusted fetch content and executed scripts can
// never observe secrets. Values are read from the daemon's own environment
// only at the moment of exec and are redacted ([REDACTED]) from every log
// path (spans, trace dumps, audit entries, stored run output).

// Redacted is the placeholder that replaces secret values in all logs.
const Redacted = "[REDACTED]"

// Vault binds a Policy to the process environment.
type Vault struct {
	policy *Policy
}

// NewVault returns a Vault enforcing p (nil policy = built-in defaults,
// which grant no tool any env secrets).
func NewVault(p *Policy) *Vault {
	if p == nil {
		p = DefaultPolicy()
	}
	return &Vault{policy: p}
}

// AllowedEnvNames returns the policy-declared env names for a tool.
// Unknown tools get nothing (fail-closed).
func (v *Vault) AllowedEnvNames(tool string) []string {
	if !IsKnownTool(tool) {
		return nil
	}
	return append([]string(nil), v.policy.Tools[tool].Env...)
}

// EnvForTool returns "K=V" pairs injected at exec time: only allowlisted
// names that are actually set in the daemon's environment. Unset names are
// skipped (no empty values leak the *names* of expected secrets either —
// see buildEnv, which only exports what is set).
func (v *Vault) EnvForTool(tool string) []string {
	var out []string
	for _, name := range v.AllowedEnvNames(tool) {
		if val, ok := os.LookupEnv(name); ok && val != "" {
			out = append(out, name+"="+val)
		}
	}
	return out
}

// SecretsSnapshot returns the current *values* of every policy-declared env
// name across all tools. Callers pass this to the redaction helpers before
// anything touches a log. Values only — names alone are not sensitive.
func (v *Vault) SecretsSnapshot() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, tp := range v.policy.Tools {
		for _, name := range tp.Env {
			if val, ok := os.LookupEnv(name); ok && val != "" {
				if _, dup := seen[val]; !dup {
					seen[val] = struct{}{}
					out = append(out, val)
				}
			}
		}
	}
	return out
}

// RedactText replaces every occurrence of each non-empty secret with
// [REDACTED]. Longer secrets are masked first so overlapping values cannot
// leave a suffix behind.
func RedactText(s string, secrets []string) string {
	ordered := append([]string(nil), secrets...)
	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			if len(ordered[j]) > len(ordered[i]) {
				ordered[i], ordered[j] = ordered[j], ordered[i]
			}
		}
	}
	for _, sec := range ordered {
		if sec == "" {
			continue
		}
		if strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, Redacted)
		}
	}
	return s
}

// RedactMap deep-copies m with every string redacted. Used for audit fields
// and span attributes so secrets can never reach the JSONL ledgers.
func RedactMap(m map[string]any, secrets []string) map[string]any {
	if m == nil || len(secrets) == 0 {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = redactValue(v, secrets)
	}
	return out
}

// RedactStrings returns a redacted copy of a string slice (argv vectors).
func RedactStrings(in []string, secrets []string) []string {
	if len(in) == 0 || len(secrets) == 0 {
		return in
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = RedactText(s, secrets)
	}
	return out
}

func redactValue(v any, secrets []string) any {
	switch t := v.(type) {
	case string:
		return RedactText(t, secrets)
	case []string:
		cp := make([]string, len(t))
		for i, s := range t {
			cp[i] = RedactText(s, secrets)
		}
		return cp
	case []any:
		cp := make([]any, len(t))
		for i, e := range t {
			cp[i] = redactValue(e, secrets)
		}
		return cp
	case map[string]any:
		return RedactMap(t, secrets)
	default:
		return v
	}
}

// baseEnvNames are the only non-secret variables a vault-restricted child
// inherits. Everything else must come from the per-tool allowlist.
var baseEnvNames = []string{
	"PATH", "HOME", "TMPDIR", "TEMP", "TMP",
	"LANG", "LC_ALL", "LC_CTYPE", "TZ", "USER", "LOGNAME", "SHELL",
}

// buildEnv constructs the child environment for a tool-bound exec: minimal
// safe base + allowlisted secrets. A nil vault means "legacy mode" (return
// nil ⇒ inherit the full parent env, preserving pre-v2 behaviour).
func buildEnv(tool string, v *Vault) []string {
	if v == nil {
		return nil
	}
	var env []string
	for _, name := range baseEnvNames {
		if val, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+val)
		}
	}
	return append(env, v.EnvForTool(tool)...)
}
