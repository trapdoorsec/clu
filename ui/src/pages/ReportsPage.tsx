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
    <div className="p-6 max-w-[1400px]">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold">Reports</h2>
        <span className="text-sm text-[var(--color-text-muted)]">{total} total</span>
      </div>

      <div className="flex gap-3 mb-4">
        <select
          value={ecosystemFilter}
          onChange={(e) => { setEcosystemFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)]"
        >
          <option value="">All Ecosystems</option>
          <option value="pypi">PyPI</option>
          <option value="npm">npm</option>
        </select>
        <label className="flex items-center gap-2 text-sm text-[var(--color-text-muted)]">
          <input
            type="checkbox"
            checked={maliciousOnly}
            onChange={(e) => { setMaliciousOnly(e.target.checked); setPage(0); }}
            className="rounded"
          />
          Malicious only
        </label>
      </div>

      {query.isLoading && <div className="text-[var(--color-text-muted)]">Loading...</div>}

      {query.data && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-[var(--color-text-muted)] text-left">
                <th className="py-2 px-2">Package</th>
                <th className="py-2 px-2">Ecosystem</th>
                <th className="py-2 px-2">Severity</th>
                <th className="py-2 px-2">Recommendation</th>
                <th className="py-2 px-2">Malicious</th>
                <th className="py-2 px-2">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr
                  key={r.id}
                  className="border-b border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] transition-colors"
                >
                  <td className="py-2 px-2 font-mono">
                    <Link
                      to={`/reports/${r.id}`}
                      className="text-[var(--color-primary)] hover:underline"
                    >
                      {r.package_name}
                    </Link>
                    {r.package_version && (
                      <span className="text-[var(--color-text-muted)] ml-1">
                        v{r.package_version}
                      </span>
                    )}
                  </td>
                  <td className="py-2 px-2 capitalize">{r.ecosystem}</td>
                  <td className="py-2 px-2">
                    <span className={cn("px-1.5 py-0.5 rounded text-xs font-medium border", severityColor(r.severity))}>
                      {r.severity} {severityLabel(r.severity)}
                    </span>
                  </td>
                  <td className="py-2 px-2 text-xs">{r.recommendation}</td>
                  <td className="py-2 px-2">
                    {r.is_malicious ? (
                      <span className="text-[var(--color-danger)]">Yes</span>
                    ) : (
                      <span className="text-[var(--color-text-muted)]">No</span>
                    )}
                  </td>
                  <td className="py-2 px-2 text-xs text-[var(--color-text-muted)]">
                    {formatTime(r.timestamp)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex justify-center gap-2 mt-4">
          <button
            disabled={page === 0}
            onClick={() => setPage(page - 1)}
            className="px-3 py-1.5 text-sm rounded border border-[var(--color-border)] bg-[var(--color-surface)] disabled:opacity-40 hover:bg-[var(--color-surface-hover)] transition-colors"
          >
            Prev
          </button>
          <span className="px-3 py-1.5 text-sm text-[var(--color-text-muted)]">
            {page + 1} / {totalPages}
          </span>
          <button
            disabled={page >= totalPages - 1}
            onClick={() => setPage(page + 1)}
            className="px-3 py-1.5 text-sm rounded border border-[var(--color-border)] bg-[var(--color-surface)] disabled:opacity-40 hover:bg-[var(--color-surface-hover)] transition-colors"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}