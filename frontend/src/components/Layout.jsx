import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth/AuthContext.jsx";
import { hasCapability } from "../auth/permissions.js";

const linkClass = ({ isActive }) =>
  isActive ? "font-semibold text-slate-900" : "text-slate-600 hover:text-slate-900";

// Frame for every logged-in page: nav on the left, who you are + logout on the right.
export default function Layout() {
  const { user, logout } = useAuth();
  return (
    <div className="min-h-screen bg-slate-100">
      <header className="flex items-center justify-between bg-white px-6 py-3 shadow">
        <nav className="flex items-center gap-4">
          <span className="font-bold text-slate-800">AidFlow</span>
          <NavLink to="/" end className={linkClass}>
            Home
          </NavLink>
          {/* Hiding the link is cosmetic; the route guard and the API do the enforcing. */}
          {hasCapability(user, "manage_users") && (
            <NavLink to="/users" className={linkClass}>
              Users
            </NavLink>
          )}
        </nav>
        <div className="flex items-center gap-3 text-sm text-slate-700">
          <span>
            {user.username} ({user.role})
          </span>
          <button onClick={logout} className="rounded border border-slate-400 px-3 py-1">
            Log out
          </button>
        </div>
      </header>
      <main className="p-6">
        <Outlet />
      </main>
    </div>
  );
}
