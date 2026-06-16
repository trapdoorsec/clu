import { useState } from "react";
import { useReports } from "@/hooks/queries";
import { formatTime, severityColor, severityLabel, cn } from "@/lib/utils";
import { Link } from "react-router-dom";

const PAGE_SIZE = 50;

export default function ReportsPage() {
  const [page, setPage] = useState(0);
  const [ecosystemFilter, setEcosystemFilter] = useState<string>("");
  const [maliciousOnly, setMaliciousOnly] = useState(false);

  const query = useReports({
    ecosystem: ecosystemFilter || undefined,
    malicious: maliciousOnly || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const reports = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="p-8 max-w-[1400px]">
      <div className="flex justify-between items-end mb-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Reports</h2>
          <p className="text-sm text-[var(--color-text-dim)] mt-1">{total} total reports</p>
        </div>
      </div>

      <div className="flex gap-3 mb-5">
        <select
          value={ecosystemFilter}
          onChange={(e) => { setEcosystemFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)] transition-all duration-150"
        >
          <option value="">All Ecosystems</option>
          <option value="pypi">PyPI</option>
          <option value="npm">npm</option>
        </select>
        <label className="flex items-center gap-2 text-sm text-[var(--color-text-muted)] cursor-pointer">
          <input
            type="checkbox"
            checked={maliciousOnly}
            onChange={(e) => { setMaliciousOnly(e.target.checked); setPage(0); }}
            className="rounded accent-[var(--color-primary)]"
          />
          Malicious only
        </label>
      </div>

      {query.isLoading && <div className="text-[var(--color-text-dim)]">Loading...</div>}

      {query.data && (
        <div className="overflow-x-auto rounded-xl border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-[var(--color-text-dim)] text-left text-xs uppercase tracking-wider">
                <th className="py-3 px-4 font-medium">Package</th>
                <th className="py-3 px-4 font-medium">Ecosystem</th>
                <th className="py-3 px-4 font-medium">Severity</th>
                <th className="py-3 px-4 font-medium">Recommendation</th>
                <th className="py-3 px-4 font-medium">Malicious</th>
                <th className="py-3 px-4 font-medium">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr
                  key={r.id}
                  className="border-b border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] transition-colors duration-100"
                >
                  <td className="py-2.5 px-4 font-mono">
                    <Link
                      to={`/reports/${r.id}`}
                      className="text-[var(--color-primary)] hover:text-[var(--color-primary-hover)] transition-colors"
                    >
                      {r.package_name}
                    </Link>
                    {r.package_version && (
                      <span className="text-[var(--color-text-dim)] ml-1">
                        v{r.package_version}
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 capitalize text-[var(--color-text-muted)]">{r.ecosystem}</td>
                  <td className="py-2.5 px-4">
                    <span className={cn("px-2 py-0.5 rounded text-xs font-medium border", severityColor(r.severity))}>
                      {r.severity} {severityLabel(r.severity)}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-xs text-[var(--color-text-muted)]">{r.recommendation}</td>
                  <td className="py-2.5 px-4">
                    {r.is_malicious ? (
                      <span className="text-[var(--color-danger)]">Yes</span>
                    ) : (
                      <span className="text-[var(--color-text-dim)]">No</span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-xs text-[var(--color-text-dim)]">
                    {formatTime(r.timestamp)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex justify-center items-center gap-3 mt-5">
          <button
            disabled={page === 0}
            onClick={() => setPage(page - 1)}
            className="px-3.5 py-1.5 text-sm rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] disabled:opacity-30 hover:bg-[var(--color-surface-hover)] hover:border-[var(--color-border-light)] transition-all duration-150"
          >
            Prev
          </button>
          <span className="text-sm text-[var(--color-text-dim)] tabular-nums">
            {page + 1} / {totalPages}
          </span>
          <button
            disabled={page >= totalPages - 1}
            onClick={() => setPage(page + 1)}
            className="px-3.5 py-1.5 text-sm rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] disabled:opacity-30 hover:bg-[var(--color-surface-hover)] hover:border-[var(--color-border-light)] transition-all duration-150"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}