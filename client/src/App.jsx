import { useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import ProtectedRoute from "./components/ProtectedRoute";
import AuthPage from "./pages/AuthPage";
import DashboardPage from "./pages/DashboardPage";
import LandingPage from "./pages/LandingPage";
import SharePage from "./pages/SharePage";
import { clearSession, getStoredToken, getStoredUser, saveSession } from "./lib/session";

export default function App() {
  const [session, setSession] = useState(() => ({
    token: getStoredToken(),
    user: getStoredUser(),
  }));

  function handleAuthenticated(token, user) {
    saveSession(token, user);
    setSession({ token, user });
  }

  function handleLogout() {
    clearSession();
    setSession({ token: "", user: null });
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/"
          element={<LandingPage isAuthenticated={Boolean(session.token)} />}
        />

        <Route
          path="/auth"
          element={
            session.token ? (
              <Navigate to="/dashboard" replace />
            ) : (
              <AuthPage onAuthenticated={handleAuthenticated} />
            )
          }
        />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute token={session.token}>
              <DashboardPage
                token={session.token}
                user={session.user}
                onLogout={handleLogout}
              />
            </ProtectedRoute>
          }
        />

        <Route path="/share/:token" element={<SharePage />} />

        <Route
          path="*"
          element={<Navigate to="/" replace />}
        />
      </Routes>
    </BrowserRouter>
  );
}
