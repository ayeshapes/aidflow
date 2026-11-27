import { useEffect, useState } from "react";
import { apiFetch } from "../api/client.js";

// Calls GET /api/health once and shows what came back.
export default function Health() {
  const [state, setState] = useState({ loading: true });

  useEffect(() => {
    let cancelled = false; // ignore the answer if the page was closed meanwhile
    apiFetch("/health")
      .then((data) => !cancelled && setState({ data }))
      .catch((error) => !cancelled && setState({ error }));
    return () => {
      cancelled = true;
    };
  }, []);

  if (state.loading) {
    return <p className="text-slate-600">Checking the backend...</p>;
  }

  if (state.error) {
    return (
      <div className="max-w-md rounded border border-red-300 bg-red-50 p-4 text-red-800">
        <p className="font-semibold">Backend check failed</p>
        <p>{state.error.message}</p>
        <p className="text-sm">
          code: {state.error.code} (HTTP {state.error.status})
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-md rounded border border-green-300 bg-green-50 p-4 text-green-900">
      <p className="font-semibold">Backend is healthy</p>
      <p>status: {state.data.status}</p>
      <p>database: {state.data.db ? "connected" : "not connected"}</p>
    </div>
  );
}
