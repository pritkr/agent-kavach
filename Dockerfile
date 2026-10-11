# ---- stage 1: Go daemon -------------------------------------------------
FROM golang:1.22-alpine AS go-build
WORKDIR /src/daemon
COPY daemon/go.mod ./
COPY daemon/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/daemon .

# ---- stage 2: TypeScript runner (build + pruned prod deps) -----------------
FROM node:22-alpine AS runner-build
WORKDIR /src/runner
COPY runner/package.json runner/package-lock.json ./
RUN npm ci
COPY runner/src ./src
COPY runner/tests ./tests
COPY runner/scripts ./scripts
COPY runner/tsconfig.json ./
RUN npm run build && npm prune --omit=dev

# ---- stage 3: web dashboard (production dist) ------------------------------
FROM node:22-alpine AS web-build
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/index.html web/vite.config.ts web/tsconfig.json ./
COPY web/src ./src
RUN npm run build

# ---- final: one small image, zero open ports by default --------------------
FROM node:22-bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -m -u 10001 kavach
WORKDIR /app
COPY --from=go-build /out/daemon /app/daemon
COPY mcp/server.py mcp/tools.json mcp/policy.py /app/mcp/
# The declarative policy manifest, read by BOTH the gateway and the daemon.
COPY policy.yaml /app/policy.yaml
COPY --from=runner-build /src/runner/dist /app/runner/dist
COPY --from=runner-build /src/runner/node_modules /app/runner/node_modules
COPY --from=runner-build /src/runner/package.json /app/runner/
COPY --from=web-build /src/web/dist /app/web-dist
COPY eval/tasks.json eval/passk.py /app/eval/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh \
  && mkdir -p /run/kavach /data/workspace \
  && chown -R kavach:kavach /app /run/kavach /data
USER kavach
ENV KAVACH_SOCKET=/run/kavach/kavach.sock \
    KAVACH_TOKEN_FILE=/run/kavach/kavach.token \
    KAVACH_WORKSPACE=/data/workspace \
    KAVACH_MCP_PORT=8077 \
    KAVACH_POLICY=/app/policy.yaml \
    KAVACH_FETCH_ALLOWLIST=example.com
# No EXPOSE: the daemon listens only on a 0600 Unix socket.
ENTRYPOINT ["/app/entrypoint.sh"]
