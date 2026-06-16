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
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] rounded-full opacity-[0.04]"
          style={{ background: "radial-gradient(ellipse, var(--color-primary), transparent 70%)" }}
        />
      </div>

      <form
        onSubmit={handleSubmit}
        className="relative w-full max-w-sm p-8 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]"
        style={{ boxShadow: "0 0 80px -20px rgba(201,162,39,0.08)" }}
      >
        <div className="flex items-center justify-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-lg bg-[var(--color-primary)] flex items-center justify-center text-black font-bold text-lg">
            C
          </div>
        </div>
        <h1 className="text-xl font-bold text-center tracking-tight">
          CLU
        </h1>
        <p className="text-[11px] uppercase tracking-[0.2em] text-[var(--color-text-dim)] text-center mb-6">
          Malware Scanner
        </p>

        <label className="block text-xs font-medium text-[var(--color-text-muted)] mb-1.5 uppercase tracking-wider" htmlFor="token">
          API Token
        </label>
        <input
          id="token"
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)] placeholder-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]/20 transition-all duration-150"
          placeholder="Enter Bearer token"
          autoFocus
        />

        {error && (
          <p className="mt-2 text-sm text-[var(--color-danger)]">{error}</p>
        )}

        <button
          type="submit"
          disabled={login.isPending || !token}
          className="mt-5 w-full rounded-md bg-[var(--color-primary)] px-4 py-2.5 text-sm font-semibold text-black hover:bg-[var(--color-primary-hover)] disabled:opacity-40 disabled:cursor-not-allowed transition-all duration-150"
        >
          {login.isPending ? "Connecting..." : "Connect"}
        </button>
      </form>
    </div>
  );
}