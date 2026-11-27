import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext.jsx";
import { hasCapability } from "./permissions.js";
import Forbidden from "../pages/Forbidden.jsx";

// Wrap routes that need a logged-in user, optionally with a capability:
//
//   <Route element={<ProtectedRoute />}>                              logged in
//   <Route element={<ProtectedRoute capability="manage_users" />}>    logged in + capability
//
// Not logged in  -> redirect to /login (and remember where they were going).
// Missing right  -> show the 403 page in place; the URL does not change.
// This is a convenience for the person using the app. The API enforces the
// same rules, so it never relies on this component.
export default function ProtectedRoute({ capability, children }) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) return <p className="p-6 text-slate-600">Loading...</p>;
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  if (capability && !hasCapability(user, capability)) return <Forbidden />;
  return children ?? <Outlet />;
}
