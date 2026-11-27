import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { apiFetch, setToken, setUnauthorizedHandler } from "../api/client.js";

// WHERE THE TOKEN LIVES, AND WHY
//
// The access token is kept in memory (client.js) AND mirrored in sessionStorage
// so a page reload does not log the person out. The options, honestly compared:
//
//  memory only
//    + Not readable from storage; gone when the tab closes.
//    - Every reload or new tab means logging in again.
//
//  sessionStorage (our choice)
//    + Survives reloads, but is private to one tab and cleared when it closes,
//      so a forgotten session does not outlive the browser tab.
//    + Not sent automatically by the browser, so it is immune to CSRF.
//    - Any JavaScript running on our origin can read it. If an XSS bug ever
//      lets an attacker run a script on the page, the token can be stolen.
//
//  localStorage
//    + Survives restarts and is shared across tabs (most convenient).
//    - Same XSS exposure as sessionStorage, but the token stays around much
//      longer and is visible to every tab. Convenience we do not need here.
//
//  httpOnly cookie
//    + JavaScript cannot read it, so XSS cannot steal the token itself (an
//      injected script could still send requests as the user while the page
//      is open). Strongest option against token theft.
//    - The browser attaches it automatically, so CSRF protection becomes
//      mandatory (SameSite, a CSRF token). It also needs backend changes
//      (Set-Cookie instead of a JSON token, CORS credentials). Worth revisiting
//      once nginx serves frontend and API from one origin.
//
// Why sessionStorage is acceptable for now: tokens are short-lived (30 minutes),
// logout revokes the token on the server (denylist), the server re-reads the
// user's role and active flag on every request, and React escapes everything it
// renders (we never use dangerouslySetInnerHTML). The real defence is still not
// having an XSS bug; a Content-Security-Policy header from nginx should be added
// as a second layer.
const STORAGE_KEY = "aidflow.token";

// Storage can throw (disabled by browser settings, quota). Auth must still
// work in memory when it does, so failures are swallowed.
function readStoredToken() {
  try {
    return sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStoredToken(value) {
  try {
    if (value) sessionStorage.setItem(STORAGE_KEY, value);
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // keep going with the in-memory token only
  }
}

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  // True until we know whether a stored token is still valid. Pages must not
  // decide "logged out" while this is true, or every reload would flash /login.
  const [loading, setLoading] = useState(true);

  // Forget the session locally (memory, storage, React state).
  const clearSession = useCallback(() => {
    setToken(null);
    writeStoredToken(null);
    setUser(null);
  }, []);

  // A 401 on a request that carried our token means the session is over.
  useEffect(() => {
    setUnauthorizedHandler(clearSession);
    return () => setUnauthorizedHandler(null);
  }, [clearSession]);

  // On first load: if a token is stored, ask the server who it belongs to.
  // The stored token is never trusted on its own; /auth/me proves it is valid.
  useEffect(() => {
    let cancelled = false;
    const stored = readStoredToken();
    if (!stored) {
      setLoading(false);
      return undefined;
    }
    setToken(stored);
    apiFetch("/auth/me")
      .then((me) => !cancelled && setUser(me))
      .catch(() => !cancelled && clearSession()) // expired, revoked, or server down: log in again
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [clearSession]);

  // Throws ApiError on failure (the login page shows its message).
  const login = useCallback(async (username, password) => {
    const { access_token } = await apiFetch("/auth/login", {
      method: "POST",
      body: { username, password },
    });
    setToken(access_token);
    try {
      const me = await apiFetch("/auth/me");
      writeStoredToken(access_token); // persist only once the token has proven itself
      setUser(me);
      return me;
    } catch (error) {
      setToken(null);
      throw error;
    }
  }, []);

  const logout = useCallback(() => {
    // Tell the server to revoke the token. apiFetch reads the token
    // synchronously when called, so the request carries it even though we
    // clear the session on the next line. We do not wait for the answer: if
    // the server is down or the token already expired, the person is still
    // logged out here, which is what they asked for.
    apiFetch("/auth/logout", { method: "POST" }).catch(() => {});
    clearSession();
  }, [clearSession]);

  const value = useMemo(() => ({ user, loading, login, logout }), [user, loading, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (ctx === null) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
