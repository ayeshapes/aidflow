import { useEffect, useState } from "react";
import { apiFetch } from "../api/client.js";
import Forbidden from "./Forbidden.jsx";

const PAGE_SIZE = 20; // the API allows 1-100

// Read-only list of users from GET /api/users (needs "manage_users").
export default function Users() {
  const [page, setPage] = useState(1);
  const [state, setState] = useState({ loading: true });

  useEffect(() => {
    let cancelled = false; // ignore a late answer for a page we already left
    setState({ loading: true });
    apiFetch(`/users?page=${page}&page_size=${PAGE_SIZE}`)
      .then((data) => !cancelled && setState({ data }))
      .catch((error) => !cancelled && setState({ error }));
    return () => {
      cancelled = true;
    };
  }, [page]);

  if (state.loading) return <p className="text-slate-600">Loading users...</p>;

  if (state.error) {
    // The server is the authority: if it says 403 (e.g. the role was changed
    // after this page loaded), show the same 403 page as the route guard.
    if (state.error.status === 403) return <Forbidden />;
    return (
      <div role="alert" className="max-w-md rounded border border-red-300 bg-red-50 p-4 text-red-800">
        <p className="font-semibold">Could not load users</p>
        <p>{state.error.message}</p>
        <p className="text-sm">
          code: {state.error.code} (HTTP {state.error.status})
        </p>
      </div>
    );
  }

  const { items, total } = state.data;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <h1 className="mb-4 text-2xl font-bold text-slate-800">Users</h1>
      <div className="overflow-x-auto">
        <table className="w-full max-w-3xl border border-slate-300 bg-white text-left text-sm">
          <thead className="bg-slate-200 text-slate-700">
            <tr>
              <th className="p-2">ID</th>
              <th className="p-2">Username</th>
              <th className="p-2">Role</th>
              <th className="p-2">Status</th>
              <th className="p-2">Created</th>
            </tr>
          </thead>
          <tbody>
            {items.map((u) => (
              <tr key={u.id} className="border-t border-slate-200">
                <td className="p-2">{u.id}</td>
                <td className="p-2">{u.username}</td>
                <td className="p-2">{u.role}</td>
                <td className="p-2">{u.is_active ? "Active" : "Deactivated"}</td>
                <td className="p-2">{new Date(u.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex items-center gap-3 text-sm text-slate-700">
        <button
          onClick={() => setPage((p) => p - 1)}
          disabled={page <= 1}
          className="rounded border border-slate-400 px-3 py-1 disabled:opacity-40"
        >
          Previous
        </button>
        <span>
          Page {page} of {pageCount} ({total} users)
        </span>
        <button
          onClick={() => setPage((p) => p + 1)}
          disabled={page >= pageCount}
          className="rounded border border-slate-400 px-3 py-1 disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}
