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
    <div className="p-6 max-w-[1400px]">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold">Quarantine</h2>
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
                <th className="py-2 px-2">Archive Size</th>
                <th className="py-2 px-2">Quarantined</th>
                <th className="py-2 px-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((q) => (
                <tr
                  key={q.id}
                  className="border-b border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] transition-colors"
                >
                  <td className="py-2 px-2 font-mono">
                    {q.package_name}
                    {q.package_version && (
                      <span className="text-[var(--color-text-muted)] ml-1">
                        v{q.package_version}
                      </span>
                    )}
                  </td>
                  <td className="py-2 px-2 capitalize">{q.ecosystem}</td>
                  <td className="py-2 px-2">
                    <span className={cn("px-1.5 py-0.5 rounded text-xs font-medium border", severityColor(q.severity))}>
                      {q.severity} {severityLabel(q.severity)}
                    </span>
                  </td>
                  <td className="py-2 px-2 text-xs">{statusLabel(q.recommendation)}</td>
                  <td className="py-2 px-2 text-xs text-[var(--color-text-muted)]">
                    {q.archive_size ? `${(q.archive_size / 1024).toFixed(1)} KB` : "-"}
                  </td>
                  <td className="py-2 px-2 text-xs text-[var(--color-text-muted)]">
                    {formatTime(q.quarantined_at)}
                  </td>
                  <td className="py-2 px-2">
                    <div className="flex gap-2">
                      <a
                        href={quarantineArchiveUrl(q.id)}
                        className="text-xs text-[var(--color-primary)] hover:underline"
                      >
                        Download
                      </a>
                      <button
                        onClick={() => {
                          if (confirm(`Delete quarantined package ${q.package_name}? This removes the archive from disk.`)) {
                            deleteMutation.mutate(q.id);
                          }
                        }}
                        className="text-xs text-[var(--color-danger)] hover:underline"
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