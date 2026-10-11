/** McpClient tests: envelope mapping, retryable classification, transport errors. */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { McpClient } from "../src/tools";
import { AgentError } from "../src/errors";

type FetchStub = (url: string, init?: { body?: string }) => Promise<unknown>;

let originalFetch: unknown;

function stubFetch(impl: FetchStub): void {
  (globalThis as Record<string, unknown>).fetch = impl;
}

function jsonResponse(body: unknown, status = 200): unknown {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

beforeEach(() => {
  originalFetch = (globalThis as Record<string, unknown>).fetch;
});

afterEach(() => {
  (globalThis as Record<string, unknown>).fetch = originalFetch;
});

describe("McpClient", () => {
  it("returns result on ok envelope", async () => {
    stubFetch(async () => jsonResponse({ ok: true, tool: "file-read", result: { content: "hi" } }));
    const c = new McpClient("http://localhost:8077");
    assert.deepEqual(await c.call("file-read", { path: "a.txt" }), { content: "hi" });
  });

  it("maps timeout tool error to retryable TIMEOUT", async () => {
    stubFetch(async () =>
      jsonResponse({ ok: false, tool: "shell-sandboxed", error: { code: "timeout", message: "too slow" } }),
    );
    const c = new McpClient("http://localhost:8077");
    const err = await c.call("shell-sandboxed", {}).then(
      () => null,
      (e: unknown) => e as AgentError,
    );
    assert.ok(err instanceof AgentError);
    assert.equal(err.code, "TIMEOUT");
    assert.equal(err.retryable, true);
  });

  it("maps invalid_args to non-retryable INVALID_ARGS", async () => {
    stubFetch(async () =>
      jsonResponse({ ok: false, tool: "file-read", error: { code: "path_outside_workspace", message: "escape" } }),
    );
    const c = new McpClient("http://localhost:8077");
    const err = await c.call("file-read", { path: "../x" }).then(
      () => null,
      (e: unknown) => e as AgentError,
    );
    assert.ok(err instanceof AgentError);
    assert.equal(err.code, "INVALID_ARGS");
    assert.equal(err.retryable, false);
  });

  it("maps HTTP 500 to retryable TRANSPORT", async () => {
    stubFetch(async () => jsonResponse({}, 500));
    const c = new McpClient("http://localhost:8077");
    const err = await c.call("shell-sandboxed", {}).then(
      () => null,
      (e: unknown) => e as AgentError,
    );
    assert.ok(err instanceof AgentError);
    assert.equal(err.code, "TRANSPORT");
    assert.equal(err.retryable, true);
  });

  it("maps connection refusal to retryable TRANSPORT", async () => {
    stubFetch(async () => {
      throw new Error("connect ECONNREFUSED");
    });
    const c = new McpClient("http://localhost:8077");
    const err = await c.call("shell-sandboxed", {}).then(
      () => null,
      (e: unknown) => e as AgentError,
    );
    assert.ok(err instanceof AgentError);
    assert.equal(err.code, "TRANSPORT");
    assert.equal(err.retryable, true);
  });

  it("posts to /tools/call with tool + args payload", async () => {
    let seenUrl = "";
    let seenBody = "";
    stubFetch(async (url: string, init?: { body?: string }) => {
      seenUrl = url;
      seenBody = init?.body ?? "";
      return jsonResponse({ ok: true, tool: "scheme-lookup", result: {} });
    });
    const c = new McpClient("http://mcp:8077");
    await c.call("scheme-lookup", { name: "fast" });
    assert.equal(seenUrl, "http://mcp:8077/tools/call");
    assert.deepEqual(JSON.parse(seenBody), { tool: "scheme-lookup", args: { name: "fast" } });
  });
});
