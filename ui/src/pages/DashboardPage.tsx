import { useStats, useLogout } from "@/hooks/queries";
import { severityLabel, statusLabel, statusColor } from "@/lib/utils";
import { Link } from "react-router-dom";

export default function DashboardPage() {
  const stats = useStats();
  const logout = useLogout();

  const s = stats.data;

  if (stats.isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-[var(--color-text-muted)]">
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
    <div className="p-6 max-w-6xl">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold">Dashboard</h2>
        <button
          onClick={logout}
          className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-danger)] transition-colors"
        >
          Logout
        </button>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-8">
        {statsCards.map((c) => (
          <Link
            key={c.label}
            to={c.href}
            className="block p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] hover:bg-[var(--color-surface-hover)] transition-colors"
          >
            <div className="text-sm text-[var(--color-text-muted)]">{c.label}</div>
            <div className="text-3xl font-bold mt-1 font-mono">{c.value}</div>
          </Link>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)]">
          <h3 className="text-sm font-semibold mb-3 text-[var(--color-text-muted)] uppercase tracking-wider">
            By Severity
          </h3>
          <div className="space-y-2">
            {Object.entries(s.findings_by_severity).map(([k, v]) => (
              <div key={k} className="flex justify-between text-sm">
                <span>{severityLabel(Number(k) * 5).replace("LOW", k === "low" ? "Low" : k === "medium" ? "Medium" : k === "high" ? "High" : "Critical")}</span>
                <span className="font-mono">{v}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)]">
          <h3 className="text-sm font-semibold mb-3 text-[var(--color-text-muted)] uppercase tracking-wider">
            By Status
          </h3>
          <div className="space-y-2">
            {Object.entries(s.findings_by_status).map(([k, v]) => (
              <div key={k} className="flex justify-between text-sm">
                <span className={statusColor(k)}>
                  {statusLabel(k)}
                </span>
                <span className="font-mono">{v}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="p-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)]">
          <h3 className="text-sm font-semibold mb-3 text-[var(--color-text-muted)] uppercase tracking-wider">
            By Ecosystem
          </h3>
          <div className="space-y-2">
            {Object.entries(s.findings_by_ecosystem).map(([k, v]) => (
              <div key={k} className="flex justify-between text-sm">
                <span className="capitalize">{k}</span>
                <span className="font-mono">{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}