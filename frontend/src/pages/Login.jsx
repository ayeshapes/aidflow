import { useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { ApiError } from "../api/client.js";
import { useAuth } from "../auth/AuthContext.jsx";

export default function Login() {
  const { user, loading, login } = useAuth();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [pending, setPending] = useState(false);

  if (loading) return <p className="p-6 text-slate-600">Loading...</p>;

  // Already logged in (or just logged in): go back to where ProtectedRoute
  // sent us from, else home.
  if (user) {
    const from = location.state?.from;
    return <Navigate to={from ? from.pathname + from.search : "/"} replace />;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError(null);
    setPending(true);
    try {
      await login(username, password);
      // Success: `user` is now set and the redirect above takes over.
    } catch (err) {
      // ApiError carries the server's {"error": {"code", "message"}}.
      setError(err instanceof ApiError ? err : new ApiError(0, "UNKNOWN_ERROR", "Something went wrong."));
      setPassword("");
      setPending(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 p-4">
      <form onSubmit={handleSubmit} className="w-full max-w-sm rounded bg-white p-6 shadow">
        <h1 className="mb-4 text-2xl font-bold text-slate-800">AidFlow - Sign in</h1>

        {error && (
          <div role="alert" className="mb-4 rounded border border-red-300 bg-red-50 p-3 text-red-800">
            <p className="font-semibold">{error.message}</p>
            <p className="text-sm">
              code: {error.code}
              {error.status ? ` (HTTP ${error.status})` : ""}
            </p>
          </div>
        )}

        <label htmlFor="username" className="block text-sm font-medium text-slate-700">
          Username
        </label>
        <input
          id="username"
          type="text"
          autoComplete="username"
          required
          maxLength={100}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="mb-3 mt-1 w-full rounded border border-slate-300 p-2"
        />

        <label htmlFor="password" className="block text-sm font-medium text-slate-700">
          Password
        </label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={256}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mb-4 mt-1 w-full rounded border border-slate-300 p-2"
        />

        <button
          type="submit"
          disabled={pending}
          className="w-full rounded bg-slate-800 p-2 text-white disabled:opacity-50"
        >
          {pending ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </div>
  );
}
