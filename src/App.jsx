import { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import * as api from "./api/client";
import "./App.css";
import "./responsive.css";

import AuthView from "./components/AuthView";
import ErrorBoundary from "./components/ErrorBoundary";
import ToastContainer from "./components/ToastContainer";

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);
  const [error, setError] = useState("");
  const [pendingVerificationEmail, setPendingVerificationEmail] = useState("");

  useEffect(() => {
    const token = api.getStoredToken();
    if (token) {
      api.setAuthToken(token);
      api.getMe().then(userData => {
        setUser(userData);
        setIsLoggedIn(true);
      }).catch(() => {
        api.setAuthToken(null);
        setIsLoggedIn(false);
      });
    }

    const handleStorageChange = (e) => {
      if (e.key === "token" && !e.newValue) {
        api.setAuthToken(null);
        setUser(null);
        setIsLoggedIn(false);
      }
    };
    window.addEventListener("storage", handleStorageChange);
    return () => window.removeEventListener("storage", handleStorageChange);
  }, []);

  const handleLogin = async (identifier, password) => {
    setError("");
    try {
      const data = await api.login(identifier, password);
      api.setAuthToken(data.access_token);
      setUser(data.user);
      setIsLoggedIn(true);
    } catch (err) {
      throw new Error(err.response?.data?.detail || "Login failed");
    }
  };

  const handleSignup = async (email, username, password) => {
    setError("");
    try {
      const data = await api.signup(email, username, password);
      if (data.requires_verification) {
        setPendingVerificationEmail(email);
      }
    } catch (err) {
      throw new Error(err.response?.data?.detail || "Signup failed");
    }
  };

  const handleVerify = async (email, code) => {
    setError("");
    try {
      const data = await api.verifyEmail(email, code);
      api.setAuthToken(data.access_token);
      setUser(data.user);
      setIsLoggedIn(true);
      setPendingVerificationEmail("");
    } catch (err) {
      throw new Error(err.response?.data?.detail || "Verification failed");
    }
  };

  const handleResendCode = async (email) => {
    setError("");
    try {
      await api.resendVerificationCode(email);
    } catch (err) {
      throw new Error(err.response?.data?.detail || "Failed to resend code");
    }
  };

  const handleForgotPassword = async (email) => {
    setError("");
    try {
      await api.forgotPassword(email);
    } catch (err) {
      throw new Error(err.response?.data?.detail || "Failed to send reset code");
    }
  };

  const handleResetPassword = async (email, code, newPassword) => {
    setError("");
    try {
      await api.resetPassword(email, code, newPassword);
    } catch (err) {
      throw new Error(err.response?.data?.detail || "Password reset failed");
    }
  };

  const handleLogout = async () => {
    await api.logout();
    api.setAuthToken(null);
    setUser(null);
    setIsLoggedIn(false);
  };

  return (
    <BrowserRouter>
      <ErrorBoundary>
        <ToastContainer />
        <Routes>
          <Route
            path="/*"
            element={
              <div className="app-container">
                {!isLoggedIn ? (
                  <AuthView
                    onLogin={handleLogin}
                    onSignup={handleSignup}
                    onVerify={handleVerify}
                    onResendCode={handleResendCode}
                    onForgotPassword={handleForgotPassword}
                    onResetPassword={handleResetPassword}
                    error={error}
                    pendingVerificationEmail={pendingVerificationEmail}
                  />
                ) : (
                  <div className="dashboard">
                    <div className="top-bar">
                      <span className="top-bar-greeting">Welcome, {user?.username}</span>
                      <button className="btn btn-ghost" onClick={handleLogout}>Logout</button>
                    </div>
                    <div className="card welcome-card">
                      <h2>You're logged in!</h2>
                      <p>This is your starting point. Build something great.</p>
                    </div>
                  </div>
                )}
              </div>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </ErrorBoundary>
    </BrowserRouter>
  );
}

export default App;
