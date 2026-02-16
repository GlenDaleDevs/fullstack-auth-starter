import { useState, useEffect } from "react";
import "./Landing.css";
import { showToast } from "../utils/toast";
import { checkUsername } from "../api/client";

export default function AuthView({
  onLogin,
  onSignup,
  onVerify,
  onResendCode,
  onForgotPassword,
  onResetPassword,
  error: externalError,
  pendingVerificationEmail,
}) {
  const [mode, setMode] = useState(pendingVerificationEmail ? "verify" : "login");
  const [email, setEmail] = useState(pendingVerificationEmail || "");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [successMessage, setSuccessMessage] = useState("");
  const [usernameStatus, setUsernameStatus] = useState(null);

  useEffect(() => {
    if (pendingVerificationEmail) {
      setMode("verify");
      setEmail(pendingVerificationEmail);
    }
  }, [pendingVerificationEmail]);

  useEffect(() => {
    if (mode !== "signup" || username.length < 3) {
      setUsernameStatus(null);
      return;
    }

    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      setUsernameStatus("invalid");
      return;
    }

    const timeout = setTimeout(async () => {
      setUsernameStatus("checking");
      try {
        const response = await checkUsername(username);
        if (response.username === username) {
          setUsernameStatus(response.available ? "available" : "taken");
        }
      } catch {
        setUsernameStatus(null);
      }
    }, 300);

    return () => clearTimeout(timeout);
  }, [username, mode]);

  const displayError = externalError || error;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccessMessage("");
    setLoading(true);

    try {
      if (mode === "signup") {
        if (password.length < 8) {
          setError("Password must be at least 8 characters");
          setLoading(false);
          return;
        }
        if (!/[a-zA-Z]/.test(password)) {
          setError("Password must contain at least one letter");
          setLoading(false);
          return;
        }
        if (!/\d/.test(password)) {
          setError("Password must contain at least one digit");
          setLoading(false);
          return;
        }
        await onSignup(email, username, password);
      } else if (mode === "verify") {
        await onVerify(email, verificationCode);
      } else if (mode === "forgot") {
        await onForgotPassword(email);
        setSuccessMessage("If an account exists with that email, we've sent a reset code.");
        switchMode("reset");
      } else if (mode === "reset") {
        if (password.length < 8) {
          setError("Password must be at least 8 characters");
          setLoading(false);
          return;
        }
        if (!/[a-zA-Z]/.test(password)) {
          setError("Password must contain at least one letter");
          setLoading(false);
          return;
        }
        if (!/\d/.test(password)) {
          setError("Password must contain at least one digit");
          setLoading(false);
          return;
        }
        await onResetPassword(email, verificationCode, password);
        setSuccessMessage("Password reset successful!");
        setTimeout(() => switchMode("login"), 2000);
      } else {
        await onLogin(email.trim(), password);
      }
    } catch (err) {
      setError(err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  const handleResendCode = async () => {
    setError("");
    setSuccessMessage("");
    setLoading(true);
    try {
      await onResendCode(email);
      setError("");
      showToast("Verification code sent! Check your email.", "success");
    } catch (err) {
      setError(err.message || "Failed to resend code");
    } finally {
      setLoading(false);
    }
  };

  const handleResendResetCode = async () => {
    setError("");
    setSuccessMessage("");
    setLoading(true);
    try {
      await onForgotPassword(email);
      setError("");
      showToast("Reset code sent! Check your email.", "success");
    } catch (err) {
      setError(err.message || "Failed to resend code");
    } finally {
      setLoading(false);
    }
  };

  const switchMode = (newMode) => {
    setMode(newMode);
    setError("");
    setSuccessMessage("");
    setVerificationCode("");
    setUsernameStatus(null);
    if (newMode !== "verify" && newMode !== "reset") {
      setEmail("");
      setUsername("");
      setPassword("");
    }
  };

  return (
    <div className="landing-container">
      <div className="landing-hero">
        <h1 className="landing-brand">Welcome</h1>
        <p className="landing-subtitle">Sign in to get started.</p>
      </div>

      <div className="auth-form-container">
        {displayError && <div className="alert-error">{displayError}</div>}
        {successMessage && <div className="alert-success">{successMessage}</div>}
        <form className="auth-form" onSubmit={handleSubmit}>
        {mode === "verify" ? (
          <>
            <div className="form-group">
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                maxLength={254}
              />
            </div>
            <div className="form-group">
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                placeholder="000000"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ""))}
                required
                className="verification-code-input"
                autoComplete="one-time-code"
              />
            </div>
            <div className="auth-actions">
              <button type="submit" className="btn btn-primary" disabled={loading || verificationCode.length !== 6}>
                {loading ? "Verifying..." : "Verify Email"}
              </button>
              <button type="button" className="btn btn-ghost" onClick={handleResendCode} disabled={loading}>
                Resend Code
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => switchMode("login")}>
                Back to Login
              </button>
            </div>
          </>
        ) : mode === "forgot" ? (
          <>
            <h2 className="auth-mode-title">Reset Password</h2>
            <div className="form-group">
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                maxLength={254}
              />
            </div>
            <div className="auth-actions">
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? "Sending..." : "Send Reset Code"}
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => switchMode("login")}>
                Back to Login
              </button>
            </div>
          </>
        ) : mode === "reset" ? (
          <>
            <h2 className="auth-mode-title">Enter Reset Code</h2>
            <p className="auth-feedback">Check your email for a 6-digit reset code</p>
            <div className="form-group">
              <input
                type="email"
                placeholder="Email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                readOnly
                maxLength={254}
              />
            </div>
            <div className="form-group">
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                placeholder="000000"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ""))}
                required
                className="verification-code-input"
                autoComplete="one-time-code"
              />
            </div>
            <div className="form-group">
              <input
                type="password"
                placeholder="New Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                maxLength={128}
              />
            </div>
            <div className="auth-actions">
              <button type="submit" className="btn btn-primary" disabled={loading || verificationCode.length !== 6}>
                {loading ? "Resetting..." : "Reset Password"}
              </button>
              <button type="button" className="btn btn-ghost" onClick={handleResendResetCode} disabled={loading}>
                Resend Code
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => switchMode("login")}>
                Back to Login
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="form-group">
              <input
                type={mode === "signup" ? "email" : "text"}
                inputMode="email"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                autoComplete={mode === "signup" ? "email" : "username"}
                placeholder={mode === "signup" ? "Email" : "Email or Username"}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                maxLength={254}
              />
            </div>

            {mode === "signup" && (
              <div className="form-group">
                <input
                  type="text"
                  placeholder="Username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  maxLength={20}
                />
                {usernameStatus && (
                  <div className={`username-feedback ${usernameStatus}`}>
                    {usernameStatus === "checking" && "Checking..."}
                    {usernameStatus === "available" && "\u2713 Username available"}
                    {usernameStatus === "taken" && "\u2717 Username taken"}
                    {usernameStatus === "invalid" && "\u2717 Letters, numbers, and underscores only"}
                  </div>
                )}
              </div>
            )}

            <div className="form-group">
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                maxLength={128}
              />
            </div>

            <div className="auth-actions">
              <button type="submit" className="btn btn-primary" disabled={loading || (mode === "signup" && (usernameStatus === "taken" || usernameStatus === "invalid" || usernameStatus === "checking"))}>
                {loading ? "Loading..." : mode === "signup" ? "Sign Up" : "Login"}
              </button>
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => switchMode(mode === "signup" ? "login" : "signup")}
              >
                {mode === "signup" ? "Already have an account?" : "Need an account?"}
              </button>
              {mode === "login" && (
                <button type="button" className="btn btn-ghost" onClick={() => switchMode("forgot")}>
                  Forgot password?
                </button>
              )}
            </div>
          </>
        )}
      </form>
      </div>
    </div>
  );
}
