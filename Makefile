.PHONY: build deps test test-go test-py test-js web-build eval docker-build proxy run verify backends clean

PREFIX ?= /tmp/agent-kavach
SOCKET := $(PREFIX)/kavach.sock
POLICY := $(CURDIR)/policy.yaml
AUDIT  := $(PREFIX)/audit.jsonl

# Test-only Python dependencies. The runtime is stdlib-only, so this is the only
# thing `make test-py` needs that a fresh machine does not already have.
deps:
	python3 -m pip install --disable-pip-version-check -r requirements-dev.txt

build:
	cd daemon && go build -o daemon .
	cd runner && npm install --no-audit --no-fund && npm run build
	cd web && npm install --no-audit --no-fund && npm run build

web-build:
	cd web && npm run build

test: test-go test-py test-js

test-go:
	cd daemon && go test ./...

test-py:
	python3 -m pytest -q mcp eval

test-js:
	cd runner && npm test

# Full eval: live MCP + fixture workspace + stub fetch host, then score.
eval:
	mkdir -p $(PREFIX)/workspace/notes $(PREFIX)/workspace/checks
	printf 'buy milk\nwrite resume\nship kavach\n' > $(PREFIX)/workspace/notes/todo.md
	printf 'print("smoke-ok")\n' > $(PREFIX)/workspace/checks/smoke.py
	KAVACH_WORKSPACE=$(PREFIX)/workspace KAVACH_FETCH_ALLOWLIST='127.0.0.1,example.com' \
	  python3 mcp/server.py --port 8077 --host 127.0.0.1 --policy $(POLICY) & echo $$! > /tmp/kavach-eval-mcp.pid
	python3 tools/stub_fetch.py & echo $$! > /tmp/kavach-eval-stub.pid
	sleep 1
	cd eval && node gen_trajs.mjs --out ./trajs --samples 3
	kill $$(cat /tmp/kavach-eval-mcp.pid) $$(cat /tmp/kavach-eval-stub.pid) || true
	python3 eval/passk.py --tasks eval/tasks.json --trajectories-dir eval/trajs

run:
	mkdir -p $(PREFIX)/workspace
	./daemon/daemon -socket $(SOCKET) -policy $(POLICY) -audit $(AUDIT) &
	python3 mcp/server.py --port 8077 --policy $(POLICY)

# Offline tamper check on the audit log: replays the hash chain and, when
# anchors are present, authenticates them too. Exit 1 = tampered or an anchor
# mismatch; exit 0 with a WARNING on stderr = chain fine but the log is
# UNANCHORED (no $KAVACH_ANCHOR_KEY, or a tail after the newest anchor).
verify:
	./daemon/daemon -verify $(AUDIT)

# What can this host actually enforce? Backends + their availability, the local
# executor's kernel controls, and the anchor's health.
backends:
	curl -s --unix-socket $(SOCKET) \
	  -H "Authorization: Bearer $$(cat $(PREFIX)/kavach.token)" \
	  http://localhost/v1/backends | python3 -m json.tool

# TCP bridge so the browser dashboard can reach the Unix-socket daemon (dev only).
proxy:
	socat TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:$(SOCKET)

docker-build:
	docker build -t agent-kavach:latest .

clean:
	rm -rf daemon/daemon runner/dist runner/node_modules web/dist web/node_modules
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
