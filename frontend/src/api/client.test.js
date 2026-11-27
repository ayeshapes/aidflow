import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiFetch, setToken, setUnauthorizedHandler } from "./client.js";

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  setToken(null);
  setUnauthorizedHandler(null);
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiFetch", () => {
  it("prepends /api and returns parsed JSON", async () => {
    fetch.mockResolvedValue(jsonResponse(200, { status: "ok", db: true }));
    const data = await apiFetch("/health");
    expect(data).toEqual({ status: "ok", db: true });
    expect(fetch.mock.calls[0][0]).toBe("/api/health");
    expect(fetch.mock.calls[0][1].method).toBe("GET");
  });

  it("sends no Authorization header when there is no token", async () => {
    fetch.mockResolvedValue(jsonResponse(200, {}));
    await apiFetch("/health");
    expect(fetch.mock.calls[0][1].headers.Authorization).toBeUndefined();
  });

  it("attaches the Bearer token once one is set", async () => {
    fetch.mockResolvedValue(jsonResponse(200, {}));
    setToken("abc123");
    await apiFetch("/health");
    expect(fetch.mock.calls[0][1].headers.Authorization).toBe("Bearer abc123");
  });

  it("sends a JSON body with a Content-Type header", async () => {
    fetch.mockResolvedValue(jsonResponse(200, {}));
    await apiFetch("/items", { method: "POST", body: { name: "rice" } });
    const options = fetch.mock.calls[0][1];
    expect(options.method).toBe("POST");
    expect(options.headers["Content-Type"]).toBe("application/json");
    expect(options.body).toBe('{"name":"rice"}');
  });

  it("parses the standard error shape into an ApiError", async () => {
    fetch.mockResolvedValue(
      jsonResponse(409, { error: { code: "STOCK_TOO_LOW", message: "Not enough stock" } })
    );
    const error = await apiFetch("/x").catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(409);
    expect(error.code).toBe("STOCK_TOO_LOW");
    expect(error.message).toBe("Not enough stock");
  });

  it("copes with an error response that is not JSON", async () => {
    fetch.mockResolvedValue(new Response("<html>Bad Gateway</html>", { status: 502 }));
    const error = await apiFetch("/x").catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(502);
    expect(error.code).toBe("UNKNOWN_ERROR");
  });

  it("reports a network failure as ApiError with status 0", async () => {
    fetch.mockRejectedValue(new TypeError("Failed to fetch"));
    const error = await apiFetch("/x").catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(0);
    expect(error.code).toBe("NETWORK_ERROR");
  });

  it("returns null for 204 No Content", async () => {
    fetch.mockResolvedValue(new Response(null, { status: 204 }));
    expect(await apiFetch("/x", { method: "DELETE" })).toBeNull();
  });
});

describe("unauthorized handler", () => {
  const unauthorized = () =>
    jsonResponse(401, { error: { code: "UNAUTHORIZED", message: "Not authenticated" } });

  it("fires on a 401 to a request that carried the token", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    setToken("abc123");
    fetch.mockResolvedValue(unauthorized());
    const error = await apiFetch("/auth/me").catch((e) => e);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(error.status).toBe(401); // the error is still thrown to the caller
  });

  it("does not fire for a 401 when no token was sent (e.g. wrong password at login)", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    fetch.mockResolvedValue(unauthorized());
    await apiFetch("/auth/login", { method: "POST", body: {} }).catch(() => {});
    expect(handler).not.toHaveBeenCalled();
  });

  it("does not fire for other errors", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    setToken("abc123");
    fetch.mockResolvedValue(jsonResponse(403, { error: { code: "FORBIDDEN", message: "no" } }));
    await apiFetch("/users").catch(() => {});
    expect(handler).not.toHaveBeenCalled();
  });

  it("ignores a late 401 for a token that has since been replaced", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    setToken("old-token");
    fetch.mockImplementation(async () => {
      setToken("new-token"); // a new login happens while the request is in flight
      return unauthorized();
    });
    await apiFetch("/users").catch(() => {});
    expect(handler).not.toHaveBeenCalled();
  });
});
