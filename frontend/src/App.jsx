import { Route, Routes } from "react-router-dom";
import ProtectedRoute from "./auth/ProtectedRoute.jsx";
import Layout from "./components/Layout.jsx";
import Home from "./pages/Home.jsx";
import Login from "./pages/Login.jsx";
import NotFound from "./pages/NotFound.jsx";
import Users from "./pages/Users.jsx";

// The Router and AuthProvider wrap this in main.jsx (and in tests).
export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      {/* Everything below needs a logged-in user. */}
      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route index element={<Home />} />

          {/* Needs a logged-in user AND the capability. */}
          <Route element={<ProtectedRoute capability="manage_users" />}>
            <Route path="users" element={<Users />} />
          </Route>

          <Route path="*" element={<NotFound />} />
        </Route>
      </Route>
    </Routes>
  );
}
