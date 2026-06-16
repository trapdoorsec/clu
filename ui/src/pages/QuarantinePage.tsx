import { useState } from "react";
import { useQuarantineList, useDeleteQuarantine } from "@/hooks/queries";
import { formatTime, severityColor, severityLabel, cn, statusLabel } from "@/lib/utils";
import { quarantineArchiveUrl } from "@/api";

export default function QuarantinePage() {
  const [page, setPage] = useState(0);
  const [ecosystemFilter, setEcosystemFilter] = useState<string>("");
  const PAGE_SIZE = 50;

  const query = useQuarantineList({
    ecosystem: ecosystemFilter || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const deleteMutation = useDeleteQuarantine();

  const items = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="p-8 max-w-[1400px]">
      <div className="flex justify-between items-end mb-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Quarantine</h2>
          <p className="text-sm text-[var(--color-text-dim)] mt-1">{total} quarantined packages</p>
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
                <th className="py-3 px-4 font-medium">Archive Size</th>
                <th className="py-3 px-4 font-medium">Quarantined</th>
                <th className="py-3 px-4 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((q) => (
                <tr
                  key={q.id}
                  className="border-b border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] transition-colors duration-100"
                >
                  <td className="py-2.5 px-4 font-mono text-[var(--color-text)]">
                    {q.package_name}
                    {q.package_version && (
                      <span className="text-[var(--color-text-dim)] ml-1">
                        v{q.package_version}
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 capitalize text-[var(--color-text-muted)]">{q.ecosystem}</td>
                  <td className="py-2.5 px-4">
                    <span className={cn("px-2 py-0.5 rounded text-xs font-medium border", severityColor(q.severity))}>
                      {q.severity} {severityLabel(q.severity)}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-xs text-[var(--color-text-muted)]">{statusLabel(q.recommendation)}</td>
                  <td className="py-2.5 px-4 text-xs text-[var(--color-text-dim)]">
                    {q.archive_size ? `${(q.archive_size / 1024).toFixed(1)} KB` : "—"}
                  </td>
                  <td className="py-2.5 px-4 text-xs text-[var(--color-text-dim)]">
                    {formatTime(q.quarantined_at)}
                  </td>
                  <td className="py-2.5 px-4">
                    <div className="flex gap-3">
                      <a
                        href={quarantineArchiveUrl(q.id)}
                        className="text-xs text-[var(--color-primary)] hover:text-[var(--color-primary-hover)] transition-colors"
                      >
                        Download
                      </a>
                      <button
                        onClick={() => {
                          if (confirm(`Delete quarantined package ${q.package_name}? This removes the archive from disk.`)) {
                            deleteMutation.mutate(q.id);
                          }
                        }}
                        className="text-xs text-[var(--color-danger)] hover:text-red-300 transition-colors"
                      >
                        Delete
                      </button>
                    </div>
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