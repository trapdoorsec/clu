import { Link, Outlet, useLocation } from "react-router-dom";
import { useHealth, useStats } from "@/hooks/queries";
import { isAuthenticated } from "@/api";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: "◇" },
  { href: "/findings", label: "Findings", icon: "◈" },
  { href: "/reports", label: "Reports", icon: "▤" },
  { href: "/rules", label: "YARA Rules", icon: "⬡" },
  { href: "/quarantine", label: "Quarantine", icon: "⊟" },
  { href: "/audit", label: "Audit Log", icon: "☰" },
];

export default function Layout() {
  const health = useHealth();
  const stats = useStats();
  const location = useLocation();
  const authenticated = isAuthenticated();

  if (!authenticated) {
    return <Outlet />;
  }

  const isActive = (href: string) =>
    href === "/" ? location.pathname === "/" : location.pathname.startsWith(href);

  return (
    <div className="flex h-screen bg-[var(--color-bg)]">
      <aside
        className="flex flex-col shrink-0 border-r border-[var(--color-border)]"
        style={{ width: "var(--sidebar-w)" }}
      >
        <div className="px-5 pt-6 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[var(--color-primary)] flex items-center justify-center text-black font-bold text-sm">
              C
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight leading-none">
                CLU
              </h1>
              <p className="text-[10px] uppercase tracking-[0.2em] text-[var(--color-text-dim)] mt-0.5">
                Scanner
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 mt-3 text-[11px]">
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                health.data?.status === "ok"
                  ? "bg-[var(--color-success)]"
                  : "bg-[var(--color-danger)]"
              }`}
              style={
                health.data?.status === "ok"
                  ? { boxShadow: "0 0 6px var(--color-success)" }
                  : { boxShadow: "0 0 6px var(--color-danger)" }
              }
            />
            <span className="text-[var(--color-text-dim)]">
              {health.data?.status === "ok" ? "Operational" : "Degraded"}
            </span>
          </div>
        </div>

        <nav className="flex-1 px-3 space-y-0.5">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.href}
              to={item.href}
              className={`flex items-center gap-2.5 px-3 py-[7px] rounded-md text-[13px] transition-all duration-150 ${
                isActive(item.href)
                  ? "bg-[var(--color-primary-ghost)] text-[var(--color-primary)] font-medium"
                  : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
              }`}
            >
              <span className="text-sm w-4 text-center">{item.icon}</span>
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="px-5 py-4 border-t border-[var(--color-border)] space-y-2">
          <div className="flex justify-between text-[11px]">
            <span className="text-[var(--color-text-dim)]">Findings</span>
            <span className="font-mono text-[var(--color-text-muted)]">{stats.data?.total_findings ?? "—"}</span>
          </div>
          <div className="flex justify-between text-[11px]">
            <span className="text-[var(--color-text-dim)]">Quarantined</span>
            <span className="font-mono text-[var(--color-text-muted)]">{stats.data?.total_quarantined ?? "—"}</span>
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}