import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="max-w-md rounded border border-slate-300 bg-white p-4 text-slate-800">
      <h1 className="text-xl font-semibold">404 - Page not found</h1>
      <Link to="/" className="mt-3 inline-block text-sm underline">
        Back to home
      </Link>
    </div>
  );
}
