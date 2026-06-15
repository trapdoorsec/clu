import { Link, Outlet, useLocation } from "react-router-dom";
import { useHealth, useStats } from "@/hooks/queries";
import { isAuthenticated } from "@/api";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard" },
  { href: "/findings", label: "Findings" },
  { href: "/reports", label: "Reports" },
  { href: "/rules", label: "YARA Rules" },
  { href: "/quarantine", label: "Quarantine" },
  { href: "/audit", label: "Audit Log" },
];

export default function Layout() {
  const health = useHealth();
  const stats = useStats();
  const location = useLocation();
  const authenticated = isAuthenticated();

  if (!authenticated) {
    return <Outlet />;
  }

  return (
    <div className="flex h-screen">
      <aside className="w-60 border-r border-[var(--color-border)] bg-[var(--color-surface)] flex flex-col shrink-0">
        <div className="p-4 border-b border-[var(--color-border)]">
          <h1 className="text-xl font-bold tracking-tight">
            <span className="text-[var(--color-primary)]">CLU</span>
          </h1>
          <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
            Malware Scanner
          </p>
          <div className="flex items-center gap-1.5 mt-2 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                health.data?.status === "ok"
                  ? "bg-[var(--color-success)]"
                  : "bg-[var(--color-danger)]"
              }`}
            />
            <span className="text-[var(--color-text-muted)]">
              {health.data?.status === "ok" ? "Healthy" : "Unhealthy"}
            </span>
          </div>
        </div>

        <nav className="flex-1 py-2">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.href}
              to={item.href}
              className={`block px-4 py-2 text-sm transition-colors ${
                (item.href === "/"
                  ? location.pathname === "/"
                  : location.pathname.startsWith(item.href))
                  ? "bg-[var(--color-surface-hover)] text-[var(--color-primary)]"
                  : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
              }`}
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="p-4 border-t border-[var(--color-border)] text-xs text-[var(--color-text-muted)]">
          <div className="flex justify-between">
            <span>Findings</span>
            <span className="font-mono">{stats.data?.total_findings ?? "-"}</span>
          </div>
          <div className="flex justify-between mt-1">
            <span>Quarantined</span>
            <span className="font-mono">{stats.data?.total_quarantined ?? "-"}</span>
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}