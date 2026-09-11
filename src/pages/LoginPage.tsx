/*
LoginPage
    │
    │ invoke("login")
    ▼
Rust login()
    │
    │ stdin JSON
    ▼
Python backend
    │
    ▼
pybis.Openbis(...)
    │
    ▼
openbis.login(...)
    │
    ▼
LoginResult
    │
    ▼
MainPage
*/

import {
  useState,
} from "react";

import type {
  SyntheticEvent,
} from "react";

import {
  login,
} from "../features/auth/auth";


interface LoginPageProps {
  onLogin: () => void;
}


export function LoginPage({
  onLogin,
}: LoginPageProps) {
  const [serverUrl, setServerUrl] =
    useState(
      "https://main.datastore.bam.de",
    );

  const [username, setUsername] =
    useState("");

  const [password, setPassword] =
    useState("");

  const [
    personalAccessToken,
    setPersonalAccessToken,
  ] = useState("");

  const [error, setError] =
    useState<string | null>(null);

  const [loading, setLoading] =
    useState(false);


  async function handleSubmit(
    event: SyntheticEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (loading) {
      return;
    }


    setError(null);
    setLoading(true);


    try {
      const result =
        await login({
          serverUrl,
          username,
          password,
          personalAccessToken,
        });


      if (result.success) {
        onLogin();
        return;
      }


      setError(
        result.error ??
          "Invalid username/password or personal access token.",
      );
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : String(error),
      );
    } finally {
      setLoading(false);
    }
  }


  return (
    <main
      className="login-page"
      aria-busy={loading}
    >
      <section
        className="login-card"
        aria-hidden={
          loading
            ? "true"
            : undefined
        }
      >
        <div className="login-header">
          <h1>
            openBIS Upload Helper
          </h1>

          <p>
            Sign in to your openBIS instance
            to continue.
          </p>
        </div>


        <form
          className="login-form"
          onSubmit={handleSubmit}
        >
          <label htmlFor="server-url">
            openBIS server
          </label>

          <input
            id="server-url"
            type="url"
            value={serverUrl}
            onChange={(event) =>
              setServerUrl(
                event.currentTarget.value,
              )
            }
            placeholder="https://main.datastore.bam.de"
            autoComplete="url"
            disabled={loading}
          />


          <label htmlFor="username">
            Username
          </label>

          <input
            id="username"
            type="text"
            value={username}
            onChange={(event) =>
              setUsername(
                event.currentTarget.value,
              )
            }
            autoComplete="username"
            autoFocus
            disabled={
              loading ||
              Boolean(
                personalAccessToken,
              )
            }
          />


          <label htmlFor="password">
            Password
          </label>

          <input
            id="password"
            type="password"
            value={password}
            onChange={(event) =>
              setPassword(
                event.currentTarget.value,
              )
            }
            autoComplete="current-password"
            disabled={
              loading ||
              Boolean(
                personalAccessToken,
              )
            }
          />


          <div className="login-separator">
            <span>or</span>
          </div>


          <label htmlFor="personal-access-token">
            Personal Access Token
          </label>

          <input
            id="personal-access-token"
            type="password"
            value={personalAccessToken}
            onChange={(event) =>
              setPersonalAccessToken(
                event.currentTarget.value,
              )
            }
            autoComplete="off"
            disabled={loading}
          />


          {error && (
            <p
              className="login-error"
              role="alert"
            >
              {error}
            </p>
          )}


          <button
            type="submit"
            disabled={loading}
          >
            Sign in
          </button>
        </form>
      </section>


      {loading && (
        <div
          className="login-loading-overlay"
          role="status"
          aria-live="polite"
          aria-label="Signing in to openBIS"
        >
          <div className="login-loading-content">
            <span
              className="login-loading-spinner"
              aria-hidden="true"
            />

            <strong>
              Signing in to openBIS
            </strong>

            <span className="login-loading-message">
              Connecting and authenticating...
            </span>
          </div>
        </div>
      )}
    </main>
  );
}