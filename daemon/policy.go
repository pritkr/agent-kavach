package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// policy.go — declarative policy manifest (v2).
//
// The daemon loads policy.yaml at boot (-policy flag) and the Python MCP
// gateway reads the same file, so allow/deny, per-tool timeouts, the network
// allowlist and the workspace root stay consistent across both enforcement
// points. stdlib only: miniyaml below parses the small subset of YAML the
// manifest uses (nested maps, scalar lists, quoted/plain scalars, comments).

// KnownTools is the closed tool universe. Requests naming anything else are
// rejected with a structured unknown_tool error (fail-closed).
var KnownTools = []string{
	"shell-sandboxed",
	"file-read",
	"web-fetch",
	"scheme-lookup",
	"eval-run",
}

// defaultToolTimeouts mirror the MCP gateway's historical per-tool defaults.
var defaultToolTimeouts = map[string]int{
	"shell-sandboxed": 30,
	"file-read":       30,
	"web-fetch":       10,
	"scheme-lookup":   10,
	"eval-run":        30,
}

// ToolPolicy is the per-tool stanza of the manifest.
type ToolPolicy struct {
	Allow      bool
	TimeoutSec int
	Env        []string
}

// Policy is the decoded manifest.
type Policy struct {
	Workspace        string
	NetworkAllowlist []string
	DefaultTimeout   int
	// Backend pins the sandbox executor: "auto" (strongest available, the
	// default) or one of docker/local/runsc. A pinned backend that cannot run is
	// a hard failure at run time — the daemon never silently downgrades, because
	// asking for gVisor and getting a host process is the failure this key
	// exists to prevent.
	Backend string
	Tools   map[string]ToolPolicy
	path    string
}

// DefaultPolicy is the built-in manifest used when no -policy file is given.
// It matches the historical hardcoded behaviour exactly.
func DefaultPolicy() *Policy {
	p := &Policy{
		Workspace:        "/tmp/agent-kavach/workspace",
		NetworkAllowlist: []string{"example.com"},
		DefaultTimeout:   120,
		Backend:          BackendAuto,
		Tools:            map[string]ToolPolicy{},
		path:             "",
	}
	for _, t := range KnownTools {
		p.Tools[t] = ToolPolicy{Allow: true, TimeoutSec: defaultToolTimeouts[t]}
	}
	return p
}

// Path returns the manifest file the policy was loaded from ("" = built-in).
func (p *Policy) Path() string { return p.path }

// IsKnown reports whether tool is in the closed tool universe.
func IsKnownTool(tool string) bool {
	for _, t := range KnownTools {
		if t == tool {
			return true
		}
	}
	return false
}

// Allowed reports whether tool may execute (unknown tools are never allowed).
func (p *Policy) Allowed(tool string) bool {
	tp, ok := p.Tools[tool]
	if !ok {
		return IsKnownTool(tool)
	}
	return tp.Allow
}

// TimeoutFor returns the per-tool wall-clock cap in seconds.
func (p *Policy) TimeoutFor(tool string) int {
	if tp, ok := p.Tools[tool]; ok && tp.TimeoutSec > 0 {
		return tp.TimeoutSec
	}
	if d, ok := defaultToolTimeouts[tool]; ok {
		return d
	}
	return 30
}

// ResolveTimeout maps a requested timeout to an effective one for a tool
// binding: <=0 means "policy default"; anything above the per-tool cap is a
// fail-closed error so callers cannot smuggle longer executions past policy.
func (p *Policy) ResolveTimeout(tool string, requested int) (int, error) {
	cap := p.TimeoutFor(tool)
	if requested <= 0 {
		return cap, nil
	}
	if requested > cap {
		return 0, fmt.Errorf("timeout_sec %d exceeds policy max %d for tool %q", requested, cap, tool)
	}
	return requested, nil
}

// LoadPolicy reads and validates a manifest file. Empty path returns the
// built-in DefaultPolicy. Unknown tools, unknown keys and out-of-range
// values are hard errors: a typo'd manifest must never silently widen access.
func LoadPolicy(path string) (*Policy, error) {
	if path == "" {
		return DefaultPolicy(), nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	raw, err := parseMiniYAML(string(data))
	if err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	p := DefaultPolicy()
	p.path = path
	for k := range raw {
		switch k {
		case "workspace", "network_allowlist", "default_timeout_sec", "backend", "tools":
		default:
			return nil, fmt.Errorf("policy: unknown top-level key %q", k)
		}
	}
	if v, ok := raw["backend"]; ok {
		s, ok := v.(string)
		if !ok || !IsKnownBackend(s) {
			return nil, fmt.Errorf("policy: backend must be one of %s", strings.Join(KnownBackends, ", "))
		}
		p.Backend = s
	}
	if v, ok := raw["workspace"]; ok {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("policy: workspace must be a non-empty string")
		}
		p.Workspace = s
	}
	if v, ok := raw["network_allowlist"]; ok {
		hosts, err := stringList(v)
		if err != nil {
			return nil, fmt.Errorf("policy: network_allowlist: %w", err)
		}
		if len(hosts) == 0 {
			return nil, fmt.Errorf("policy: network_allowlist must not be empty")
		}
		p.NetworkAllowlist = hosts
	}
	if v, ok := raw["default_timeout_sec"]; ok {
		n, ok := toInt(v)
		if !ok || n < 1 || n > 1800 {
			return nil, fmt.Errorf("policy: default_timeout_sec must be 1..1800")
		}
		p.DefaultTimeout = n
	}
	if v, ok := raw["tools"]; ok {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("policy: tools must be a mapping")
		}
		for name, entry := range m {
			if !IsKnownTool(name) {
				return nil, fmt.Errorf("policy: unknown tool %q", name)
			}
			tp := ToolPolicy{Allow: true, TimeoutSec: defaultToolTimeouts[name]}
			if entry != nil {
				em, ok := entry.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("policy: tools.%s must be a mapping", name)
				}
				for fk := range em {
					switch fk {
					case "allow", "timeout_sec", "env":
					default:
						return nil, fmt.Errorf("policy: unknown key tools.%s.%s", name, fk)
					}
				}
				if av, ok := em["allow"]; ok {
					b, ok := av.(bool)
					if !ok {
						return nil, fmt.Errorf("policy: tools.%s.allow must be true/false", name)
					}
					tp.Allow = b
				}
				if tv, ok := em["timeout_sec"]; ok {
					n, ok := toInt(tv)
					if !ok || n < 1 || n > 30 {
						return nil, fmt.Errorf("policy: tools.%s.timeout_sec must be 1..30", name)
					}
					tp.TimeoutSec = n
				}
				if ev, ok := em["env"]; ok {
					names, err := stringList(ev)
					if err != nil {
						return nil, fmt.Errorf("policy: tools.%s.env: %w", name, err)
					}
					for _, n := range names {
						if !validEnvName(n) {
							return nil, fmt.Errorf("policy: tools.%s.env: invalid env name %q", name, n)
						}
					}
					tp.Env = names
				}
			}
			p.Tools[name] = tp
		}
	}
	return p, nil
}

func stringList(v any) ([]string, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("must be a list")
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("list items must be strings")
		}
		out = append(out, s)
	}
	return out, nil
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	default:
		return 0, false
	}
}

func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// --- miniyaml: the manifest subset (maps, scalar lists, scalars, comments) ---

type yamlLine struct {
	indent  int
	content string
}

func splitYAMLLines(src string) ([]yamlLine, error) {
	var out []yamlLine
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if line == "" {
			continue
		}
		trimmed := strings.TrimLeft(line, " ")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(line, "\t") && strings.HasPrefix(line, "\t") {
			return nil, fmt.Errorf("tabs are not allowed for indentation")
		}
		indent := len(line) - len(trimmed)
		out = append(out, yamlLine{indent: indent, content: stripComment(trimmed)})
	}
	return out, nil
}

// stripComment cuts a trailing # comment (only when outside quotes and
// preceded by whitespace, so values like `*.test#x` survive intact).
func stripComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimRight(s[:i], " \t")
		}
	}
	return s
}

// parseMiniYAML parses the manifest subset into map[string]any with
// string/int/bool/nil/[]any/map[string]any leaves.
func parseMiniYAML(src string) (map[string]any, error) {
	lines, err := splitYAMLLines(src)
	if err != nil {
		return nil, err
	}
	pos := 0
	m, err := parseMapBlock(lines, &pos, -1)
	if err != nil {
		return nil, err
	}
	if pos != len(lines) {
		return nil, fmt.Errorf("unexpected content at %q", lines[pos].content)
	}
	return m, nil
}

func parseMapBlock(lines []yamlLine, pos *int, parent int) (map[string]any, error) {
	m := map[string]any{}
	for *pos < len(lines) {
		ln := lines[*pos]
		if ln.indent <= parent {
			break
		}
		if strings.HasPrefix(ln.content, "- ") || ln.content == "-" {
			return nil, fmt.Errorf("unexpected list item %q (want key: value)", ln.content)
		}
		key, val, found := splitKey(ln.content)
		if !found {
			return nil, fmt.Errorf("bad mapping line %q (want key: value)", ln.content)
		}
		*pos++
		if val != "" {
			sv, err := parseScalar(val)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			m[key] = sv
			continue
		}
		// Empty value: nested block follows, or explicit null.
		if *pos < len(lines) && lines[*pos].indent > ln.indent {
			next := lines[*pos].content
			if strings.HasPrefix(next, "- ") || next == "-" {
				lst, err := parseListBlock(lines, pos, ln.indent)
				if err != nil {
					return nil, err
				}
				m[key] = lst
			} else {
				child, err := parseMapBlock(lines, pos, ln.indent)
				if err != nil {
					return nil, err
				}
				m[key] = child
			}
		} else {
			m[key] = nil
		}
	}
	return m, nil
}

func parseListBlock(lines []yamlLine, pos *int, parent int) ([]any, error) {
	var out []any
	for *pos < len(lines) {
		ln := lines[*pos]
		if ln.indent <= parent {
			break
		}
		if !(strings.HasPrefix(ln.content, "- ") || ln.content == "-") {
			break
		}
		item := ""
		if len(ln.content) > 1 {
			item = strings.TrimSpace(ln.content[1:])
		}
		*pos++
		if item == "" {
			out = append(out, "")
			continue
		}
		if strings.Contains(item, ": ") || strings.HasSuffix(item, ":") {
			return nil, fmt.Errorf("nested mappings in lists are not supported: %q", ln.content)
		}
		sv, err := parseScalar(item)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, nil
}

// splitKey splits "key: value" on the first colon that ends the key: either
// end-of-line ("key:") or colon+space ("key: value"). Colons inside plain
// values (URLs, times) are left alone.
func splitKey(s string) (key, val string, found bool) {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == ':' && (i+1 == len(s) || s[i+1] == ' ' || s[i+1] == '\t') {
			key = strings.TrimSpace(s[:i])
			val = strings.TrimSpace(s[i+1:])
			if key == "" {
				return "", "", false
			}
			return key, val, true
		}
	}
	return "", "", false
}

func parseScalar(s string) (any, error) {
	if s == "[]" {
		return []any{}, nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			return []any{}, nil
		}
		var out []any
		for _, part := range splitFlow(inner) {
			sv, err := parseScalar(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			out = append(out, sv)
		}
		return out, nil
	}
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		if s[0] == '"' {
			unq, err := strconv.Unquote(s)
			if err != nil {
				return nil, fmt.Errorf("bad double-quoted string %q", s)
			}
			return unq, nil
		}
		return s[1 : len(s)-1], nil
	}
	switch strings.ToLower(s) {
	case "true", "yes":
		return true, nil
	case "false", "no":
		return false, nil
	case "null", "~":
		return nil, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	return s, nil
}

func splitFlow(s string) []string {
	var parts []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			cur.WriteByte(c)
			continue
		}
		if c == ',' {
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	parts = append(parts, cur.String())
	return parts
}
