import { useState } from "react";
import { useAuditLog } from "@/hooks/queries";
import { formatTime } from "@/lib/utils";

const PAGE_SIZE = 50;

export default function AuditPage() {
  const [page, setPage] = useState(0);
  const [actionFilter, setActionFilter] = useState<string>("");
  const [entityFilter, setEntityFilter] = useState<string>("");

  const query = useAuditLog({
    action: actionFilter || undefined,
    entity_type: entityFilter || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const entries = query.data?.entries ?? [];
  const total = query.data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="p-8 max-w-[1400px]">
      <div className="flex justify-between items-end mb-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Audit Log</h2>
          <p className="text-sm text-[var(--color-text-dim)] mt-1">{total} entries</p>
        </div>
      </div>

      <div className="flex gap-3 mb-5">
        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)] transition-all duration-150"
        >
          <option value="">All Actions</option>
          <option value="update">Update</option>
          <option value="delete">Delete</option>
          <option value="bulk_update">Bulk Update</option>
        </select>
        <select
          value={entityFilter}
          onChange={(e) => { setEntityFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)] transition-all duration-150"
        >
          <option value="">All Entities</option>
          <option value="finding">Finding</option>
          <option value="quarantine">Quarantine</option>
        </select>
      </div>

      {query.isLoading && <div className="text-[var(--color-text-dim)]">Loading...</div>}

      {query.data && (
        <div className="overflow-x-auto rounded-xl border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-[var(--color-text-dim)] text-left text-xs uppercase tracking-wider">
                <th className="py-3 px-4 font-medium">Timestamp</th>
                <th className="py-3 px-4 font-medium">Action</th>
                <th className="py-3 px-4 font-medium">Entity</th>
                <th className="py-3 px-4 font-medium">Entity ID</th>
                <th className="py-3 px-4 font-medium">Actor</th>
                <th className="py-3 px-4 font-medium">Details</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr
                  key={e.id}
                  className="border-b border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] transition-colors duration-100"
                >
                  <td className="py-2.5 px-4 text-xs text-[var(--color-text-dim)]">
                    {formatTime(e.timestamp)}
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-[var(--color-surface)] border border-[var(--color-border)] text-[var(--color-text-muted)]">
                      {e.action}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 capitalize text-[var(--color-text-muted)]">{e.entity_type}</td>
                  <td className="py-2.5 px-4 font-mono text-xs text-[var(--color-text)]">{e.entity_id}</td>
                  <td className="py-2.5 px-4 text-xs text-[var(--color-text-muted)]">{e.actor}</td>
                  <td className="py-2.5 px-4 text-xs text-[var(--color-text-dim)] max-w-xs truncate">
                    {e.details ?? "—"}
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