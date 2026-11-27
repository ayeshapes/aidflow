// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App.jsx";
import { setToken } from "./api/client.js";
import { AuthProvider } from "./auth/AuthContext.jsx";

const ADMIN = { id: 1, username: "alice", role: "admin", is_active: true, created_at: "2026-01-01T00:00:00Z" };
const WAREHOUSE = { ...ADMIN, id: 2, username: "walt", role: "warehouse" };

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const apiError = (status, code, message) => json(status, { error: { code, message } });

// Fake backend: routes maps "METHOD /path" (query string ignored) to a response factory.
// Anything not listed is a test failure waiting to be noticed, so it returns 500.
function mockApi(routes) {
  fetch.mockImplementation(async (url, options = {}) => {
    const key = `${options.method ?? "GET"} ${url.split("?")[0]}`;
    const handler = routes[key];
    return handler ? handler(options) : apiError(500, "UNMOCKED", `no mock for ${key}`);
  });
}

const callsTo = (key) =>
  fetch.mock.calls.filter(([url, o]) => `${o?.method ?? "GET"} ${url.split("?")[0]}` === key);

function renderApp(path = "/") {
  return render(
    <MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
}

async function signIn(user, username = "alice", password = "correct-horse-battery") {
  await user.type(await screen.findByLabelText("Username"), username);
  await user.type(screen.getByLabelText("Password"), password);
  await user.click(screen.getByRole("button", { name: "Sign in" }));
}

const usersPage = { items: [ADMIN, WAREHOUSE], total: 2, page: 1, page_size: 20 };

beforeEach(() => {
  sessionStorage.clear();
  setToken(null);
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("route guard", () => {
  it("sends an anonymous visitor to the login page", async () => {
    mockApi({});
    renderApp("/users");
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeTruthy();
    expect(callsTo("GET /users")).toHaveLength(0);
  });

  it("shows the 403 page, without calling the API, when the role lacks the capability", async () => {
    sessionStorage.setItem("aidflow.token", "tok");
    mockApi({ "GET /api/auth/me": () => json(200, WAREHOUSE) });
    renderApp("/users");
    expect(await screen.findByText(/403 - Forbidden/)).toBeTruthy();
    expect(screen.getByText(/Your role \(warehouse\)/)).toBeTruthy();
    expect(callsTo("GET /api/users")).toHaveLength(0);
    // nav does not offer the Users link to this role
    expect(screen.queryByRole("link", { name: "Users" })).toBeNull();
  });

  it("lets an admin see the users page", async () => {
    sessionStorage.setItem("aidflow.token", "tok");
    mockApi({
      "GET /api/auth/me": () => json(200, ADMIN),
      "GET /api/users": () => json(200, usersPage),
    });
    renderApp("/users");
    expect(await screen.findByRole("cell", { name: "walt" })).toBeTruthy();
    expect(screen.getByText(/Page 1 of 1 \(2 users\)/)).toBeTruthy();
  });

  it("shows the 403 page if the server itself answers 403", async () => {
    sessionStorage.setItem("aidflow.token", "tok");
    mockApi({
      "GET /api/auth/me": () => json(200, ADMIN),
      "GET /api/users": () => apiError(403, "FORBIDDEN", "You do not have permission to do this"),
    });
    renderApp("/users");
    expect(await screen.findByText(/403 - Forbidden/)).toBeTruthy();
  });
});

describe("login", () => {
  it("logs in, stores the token, and returns the person to the page they wanted", async () => {
    mockApi({
      "POST /api/auth/login": () => json(200, { access_token: "tok-1", token_type: "bearer", expires_in: 1800 }),
      "GET /api/auth/me": () => json(200, ADMIN),
      "GET /api/users": () => json(200, usersPage),
    });
    const user = userEvent.setup();
    renderApp("/users"); // not logged in -> /login, remembering /users
    await signIn(user);

    expect(await screen.findByRole("cell", { name: "walt" })).toBeTruthy();
    expect(sessionStorage.getItem("aidflow.token")).toBe("tok-1");
    expect(JSON.parse(callsTo("POST /api/auth/login")[0][1].body)).toEqual({
      username: "alice",
      password: "correct-horse-battery",
    });
    expect(callsTo("GET /api/auth/me")[0][1].headers.Authorization).toBe("Bearer tok-1");
  });

  it("shows the server's error message and stores nothing on failure", async () => {
    mockApi({
      "POST /api/auth/login": () => apiError(401, "UNAUTHORIZED", "Invalid username or password"),
    });
    const user = userEvent.setup();
    renderApp("/login");
    await signIn(user, "alice", "wrong-password-123");

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Invalid username or password");
    expect(alert.textContent).toContain("UNAUTHORIZED");
    expect(sessionStorage.getItem("aidflow.token")).toBeNull();
    expect(screen.getByLabelText("Password").value).toBe(""); // password cleared
  });

  it("shows a validation error from the standard shape", async () => {
    mockApi({
      "POST /api/auth/login": () => apiError(422, "VALIDATION_ERROR", "Validation failed: body.username: too short"),
    });
    const user = userEvent.setup();
    renderApp("/login");
    await signIn(user);
    expect((await screen.findByRole("alert")).textContent).toContain("Validation failed");
  });

  it("shows a network failure", async () => {
    fetch.mockRejectedValue(new TypeError("Failed to fetch"));
    const user = userEvent.setup();
    renderApp("/login");
    await signIn(user);
    expect((await screen.findByRole("alert")).textContent).toContain("Cannot reach the server.");
  });

  it("does not keep the token if /auth/me fails right after login", async () => {
    mockApi({
      "POST /api/auth/login": () => json(200, { access_token: "tok-1", token_type: "bearer", expires_in: 1800 }),
      "GET /api/auth/me": () => apiError(500, "INTERNAL_ERROR", "Internal server error"),
    });
    const user = userEvent.setup();
    renderApp("/login");
    await signIn(user);
    expect((await screen.findByRole("alert")).textContent).toContain("Internal server error");
    expect(sessionStorage.getItem("aidflow.token")).toBeNull();
  });
});

describe("session", () => {
  it("restores the session from sessionStorage on reload", async () => {
    sessionStorage.setItem("aidflow.token", "tok-1");
    mockApi({
      "GET /api/auth/me": () => json(200, ADMIN),
      "GET /api/health": () => json(200, { status: "ok", db: true }),
    });
    renderApp("/");
    expect(await screen.findByText("Welcome, alice")).toBeTruthy();
    expect(callsTo("GET /api/auth/me")[0][1].headers.Authorization).toBe("Bearer tok-1");
  });

  it("drops a stored token the server no longer accepts", async () => {
    sessionStorage.setItem("aidflow.token", "stale");
    mockApi({ "GET /api/auth/me": () => apiError(401, "UNAUTHORIZED", "Not authenticated") });
    renderApp("/");
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeTruthy();
    expect(sessionStorage.getItem("aidflow.token")).toBeNull();
  });

  it("logs out locally when the token expires during use", async () => {
    sessionStorage.setItem("aidflow.token", "tok-1");
    mockApi({
      "GET /api/auth/me": () => json(200, ADMIN),
      "GET /api/users": () => apiError(401, "UNAUTHORIZED", "Not authenticated"),
    });
    renderApp("/users");
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeTruthy();
    expect(sessionStorage.getItem("aidflow.token")).toBeNull();
  });

  it("logout revokes the token on the server, clears storage, and returns to login", async () => {
    sessionStorage.setItem("aidflow.token", "tok-1");
    mockApi({
      "GET /api/auth/me": () => json(200, ADMIN),
      "GET /api/health": () => json(200, { status: "ok", db: true }),
      "POST /api/auth/logout": () => json(200, { message: "Logged out" }),
    });
    const user = userEvent.setup();
    renderApp("/");
    await user.click(await screen.findByRole("button", { name: "Log out" }));

    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeTruthy();
    expect(sessionStorage.getItem("aidflow.token")).toBeNull();
    await waitFor(() => expect(callsTo("POST /api/auth/logout")).toHaveLength(1));
    expect(callsTo("POST /api/auth/logout")[0][1].headers.Authorization).toBe("Bearer tok-1");
  });

  it("logout still works when the server is unreachable", async () => {
    sessionStorage.setItem("aidflow.token", "tok-1");
    mockApi({
      "GET /api/auth/me": () => json(200, ADMIN),
      "GET /api/health": () => json(200, { status: "ok", db: true }),
    });
    const user = userEvent.setup();
    renderApp("/");
    await screen.findByText("Welcome, alice");
    fetch.mockRejectedValue(new TypeError("Failed to fetch"));
    await user.click(screen.getByRole("button", { name: "Log out" }));
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeTruthy();
    expect(sessionStorage.getItem("aidflow.token")).toBeNull();
  });
});
