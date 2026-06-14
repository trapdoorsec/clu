import { type FormEvent, useState } from "react";
import { useLogin } from "@/hooks/queries";

export default function LoginPage() {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const login = useLogin();

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    login.mutate(
      { token },
      {
        onError: (err) => {
          if (err instanceof Error) {
            setError(err.message);
          } else {
            setError("Authentication failed");
          }
        },
      }
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-[var(--color-bg)]">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm p-8 bg-[var(--color-surface)] rounded-lg border border-[var(--color-border)]"
      >
        <h1 className="text-2xl font-bold text-center mb-1">
          <span className="text-[var(--color-primary)]">CLU</span>
        </h1>
        <p className="text-sm text-[var(--color-text-muted)] text-center mb-6">
          Malware Scanner
        </p>

        <label className="block text-sm font-medium mb-1.5" htmlFor="token">
          API Token
        </label>
        <input
          id="token"
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)] placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary)]"
          placeholder="Enter Bearer token"
          autoFocus
        />

        {error && (
          <p className="mt-2 text-sm text-[var(--color-danger)]">{error}</p>
        )}

        <button
          type="submit"
          disabled={login.isPending || !token}
          className="mt-4 w-full rounded-md bg-[var(--color-primary)] px-4 py-2 text-sm font-medium text-white hover:bg-[var(--color-primary-hover)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {login.isPending ? "Connecting..." : "Connect"}
        </button>
      </form>
    </div>
  );
}