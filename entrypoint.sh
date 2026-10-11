#!/bin/sh
# Start the MCP tool server (loopback only) then exec the Go daemon (Unix socket).
#
# Both processes read the same policy.yaml manifest: the gateway (--policy) and
# the daemon (-policy). A malformed manifest makes the gateway exit 2 and the
# daemon refuse to boot — fail closed, never silently wider defaults.
#
# Every path is overridable so the image layout can be smoke-tested outside a
# container; the defaults are exactly what the Dockerfile lays down.
set -eu
APP="${KAVACH_HOME:-/app}"
POLICY="${KAVACH_POLICY:-$APP/policy.yaml}"
SOCKET="${KAVACH_SOCKET:-/run/kavach/kavach.sock}"
WORKSPACE="${KAVACH_WORKSPACE:-/data/workspace}"

mkdir -p "$(dirname "$SOCKET")" "$WORKSPACE"
python3 "$APP/mcp/server.py" \
  --host 127.0.0.1 --port "${KAVACH_MCP_PORT:-8077}" \
  --policy "$POLICY" --workspace "$WORKSPACE" &
exec "$APP/daemon" \
  -socket "$SOCKET" \
  -token "${KAVACH_TOKEN_FILE:-/run/kavach/kavach.token}" \
  -policy "$POLICY" \
  -workspace "$WORKSPACE" \
  -audit "${KAVACH_AUDIT:-/data/audit.jsonl}" \
  -trace "${KAVACH_TRACE:-/data/trace.json}"
