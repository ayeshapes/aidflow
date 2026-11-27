import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext.jsx";

export default function Forbidden() {
  const { user } = useAuth();
  return (
    <div className="max-w-md rounded border border-amber-300 bg-amber-50 p-4 text-amber-900">
      <h1 className="text-xl font-semibold">403 - Forbidden</h1>
      <p className="mt-2">
        {user ? `Your role (${user.role}) does not` : "You do not"} have permission to view this page.
      </p>
      <Link to="/" className="mt-3 inline-block text-sm underline">
        Back to home
      </Link>
    </div>
  );
}
