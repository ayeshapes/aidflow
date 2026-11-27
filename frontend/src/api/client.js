// The only place the frontend talks to the backend.
//  - prepends /api to every path:   apiFetch("/health")  ->  GET /api/health
//  - attaches "Authorization: Bearer <token>" when a token has been set
//  - turns the backend's {"error": {"code", "message"}} into an ApiError

// The token lives in this module variable. Whoever calls setToken() (AuthContext)
// decides whether to also persist it; see the trade-off notes in auth/AuthContext.jsx.
let token = null;

export function setToken(newToken) {
  token = newToken;
}

// Called when the server answers 401 to a request that carried our token, i.e.
// the session is over (expired, logged out elsewhere, user disabled). AuthContext
// uses it to drop the user and send them to /login. A 401 on /auth/login itself
// does not trigger it: no token is set at that point.
let unauthorizedHandler = null;

export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = handler;
}

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiError";
    this.status = status; // HTTP status, or 0 if the server was unreachable
    this.code = code;     // e.g. "NOT_FOUND"
  }
}

export async function apiFetch(path, { method = "GET", body } = {}) {
  const sentToken = token; // remember which token this request used
  const headers = { Accept: "application/json" };
  if (sentToken) headers.Authorization = `Bearer ${sentToken}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  let response;
  try {
    response = await fetch(`/api${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "NETWORK_ERROR", "Cannot reach the server.");
  }

  if (response.ok) {
    return response.status === 204 ? null : response.json();
  }

  // Error: read the standard shape, but cope if the body is not JSON (e.g. a proxy error page).
  let code = "UNKNOWN_ERROR";
  let message = `Request failed (${response.status})`;
  try {
    const data = await response.json();
    if (data && data.error) {
      code = data.error.code;
      message = data.error.message;
    }
  } catch {
    // keep the defaults
  }
  // Only react if the session that sent this request is still the current one;
  // a late 401 from an old token must not log out a newer login.
  if (response.status === 401 && sentToken && sentToken === token && unauthorizedHandler) {
    unauthorizedHandler();
  }
  throw new ApiError(response.status, code, message);
}
