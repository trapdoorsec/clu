import { useStats, useLogout } from "@/hooks/queries";
import { severityLabel, statusLabel, statusColor } from "@/lib/utils";
import { Link } from "react-router-dom";

export default function DashboardPage() {
  const stats = useStats();
  const logout = useLogout();

  const s = stats.data;

  if (stats.isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-[var(--color-text-dim)]">
        Loading...
      </div>
    );
  }

  if (stats.error || !s) {
    return (
      <div className="flex items-center justify-center h-full text-[var(--color-danger)]">
        Failed to load stats
      </div>
    );
  }

  const statsCards = [
    { label: "Total Findings", value: s.total_findings, href: "/findings" },
    { label: "Total Reports", value: s.total_reports, href: "/reports" },
    { label: "Quarantined", value: s.total_quarantined, href: "/quarantine" },
    { label: "New (24h)", value: s.recent_findings_24h, href: "/findings?status=new" },
  ];

  return (
    <div className="p-8 max-w-6xl">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
          <p className="text-sm text-[var(--color-text-dim)] mt-1">Overview of scanner activity</p>
        </div>
        <button
          onClick={logout}
          className="text-xs text-[var(--color-text-dim)] hover:text-[var(--color-danger)] transition-colors uppercase tracking-wider"
        >
          Logout
        </button>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-8">
        {statsCards.map((c) => (
          <Link
            key={c.label}
            to={c.href}
            className="group block p-5 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] hover:border-[var(--color-primary-dim)] transition-all duration-200"
          >
            <div className="text-xs font-medium text-[var(--color-text-dim)] uppercase tracking-wider mb-2">
              {c.label}
            </div>
            <div className="text-3xl font-bold font-mono tracking-tight group-hover:text-[var(--color-primary)] transition-colors duration-200">
              {c.value}
            </div>
          </Link>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="p-5 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
          <h3 className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[var(--color-text-dim)] mb-4">
            By Severity
          </h3>
          <div className="space-y-3">
            {Object.entries(s.findings_by_severity).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between text-sm">
                <span className="text-[var(--color-text-muted)]">
                  {severityLabel(Number(k) * 5).replace("LOW", k === "low" ? "Low" : k === "medium" ? "Medium" : k === "high" ? "High" : "Critical")}
                </span>
                <span className="font-mono tabular-nums text-[var(--color-text)]">{v}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="p-5 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
          <h3 className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[var(--color-text-dim)] mb-4">
            By Status
          </h3>
          <div className="space-y-3">
            {Object.entries(s.findings_by_status).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between text-sm">
                <span className={statusColor(k)}>
                  {statusLabel(k)}
                </span>
                <span className="font-mono tabular-nums text-[var(--color-text)]">{v}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="p-5 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
          <h3 className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[var(--color-text-dim)] mb-4">
            By Ecosystem
          </h3>
          <div className="space-y-3">
            {Object.entries(s.findings_by_ecosystem).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between text-sm">
                <span className="text-[var(--color-text-muted)] capitalize">{k}</span>
                <span className="font-mono tabular-nums text-[var(--color-text)]">{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}