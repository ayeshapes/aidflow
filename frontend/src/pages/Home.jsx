import { useAuth } from "../auth/AuthContext.jsx";
import Health from "./Health.jsx";

export default function Home() {
  const { user } = useAuth();
  return (
    <div>
      <h1 className="mb-4 text-2xl font-bold text-slate-800">Welcome, {user.username}</h1>
      <Health />
    </div>
  );
}
