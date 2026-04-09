import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { loginUser, registerUser } from "../lib/api";

const initialLogin = {
  email: "",
  password: "",
};

const initialRegister = {
  name: "",
  email: "",
  password: "",
  confirmPassword: "",
};

export default function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState("login");
  const [loginForm, setLoginForm] = useState(initialLogin);
  const [registerForm, setRegisterForm] = useState(initialRegister);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const title = useMemo(
    () =>
      mode === "login"
        ? "Welcome back to VaultMesh"
        : "Create your zero-knowledge vault",
    [mode],
  );

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      if (mode === "login") {
        const result = await loginUser({
          email: loginForm.email,
          password: loginForm.password,
        });
        onAuthenticated(result.token, result.user);
        return;
      }

      if (registerForm.password !== registerForm.confirmPassword) {
        throw new Error("Password confirmation does not match.");
      }

      const result = await registerUser({
        name: registerForm.name,
        email: registerForm.email,
        password: registerForm.password,
      });
      onAuthenticated(result.token, result.user);
    } catch (submitError) {
      setError(submitError.message || "Unable to authenticate.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page auth-page">
      <section className="hero-panel reveal-up">
        <p className="eyebrow">Zero-Knowledge Secure File Sharing</p>
        <h1>{title}</h1>
        <p className="hero-copy">
          Files are encrypted directly in your browser with AES-GCM before upload.
          The server stores only ciphertext, metadata, and access policies.
        </p>
        <p className="hero-link-row">
          <Link to="/">Back to project overview</Link>
        </p>
      </section>

      <section className="panel auth-panel reveal-up">
        <div className="mode-switch" role="tablist" aria-label="Auth mode">
          <button
            type="button"
            className={mode === "login" ? "active" : ""}
            onClick={() => {
              setMode("login");
              setError("");
            }}
          >
            Login
          </button>
          <button
            type="button"
            className={mode === "register" ? "active" : ""}
            onClick={() => {
              setMode("register");
              setError("");
            }}
          >
            Register
          </button>
        </div>

        <form className="form-grid" onSubmit={handleSubmit}>
          {mode === "register" ? (
            <>
              <label>
                Full name
                <input
                  type="text"
                  value={registerForm.name}
                  onChange={(event) =>
                    setRegisterForm((current) => ({
                      ...current,
                      name: event.target.value,
                    }))
                  }
                  minLength={2}
                  required
                />
              </label>

              <label>
                Email
                <input
                  type="email"
                  value={registerForm.email}
                  onChange={(event) =>
                    setRegisterForm((current) => ({
                      ...current,
                      email: event.target.value,
                    }))
                  }
                  required
                />
              </label>

              <label>
                Password
                <input
                  type="password"
                  value={registerForm.password}
                  onChange={(event) =>
                    setRegisterForm((current) => ({
                      ...current,
                      password: event.target.value,
                    }))
                  }
                  minLength={8}
                  required
                />
              </label>

              <label>
                Confirm password
                <input
                  type="password"
                  value={registerForm.confirmPassword}
                  onChange={(event) =>
                    setRegisterForm((current) => ({
                      ...current,
                      confirmPassword: event.target.value,
                    }))
                  }
                  minLength={8}
                  required
                />
              </label>
            </>
          ) : (
            <>
              <label>
                Email
                <input
                  type="email"
                  value={loginForm.email}
                  onChange={(event) =>
                    setLoginForm((current) => ({
                      ...current,
                      email: event.target.value,
                    }))
                  }
                  required
                />
              </label>

              <label>
                Password
                <input
                  type="password"
                  value={loginForm.password}
                  onChange={(event) =>
                    setLoginForm((current) => ({
                      ...current,
                      password: event.target.value,
                    }))
                  }
                  required
                />
              </label>
            </>
          )}

          {error ? <p className="status error">{error}</p> : null}

          <button className="btn primary" type="submit" disabled={loading}>
            {loading
              ? "Please wait..."
              : mode === "login"
                ? "Unlock dashboard"
                : "Create secure account"}
          </button>
        </form>
      </section>
    </main>
  );
}
