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
    <div className="p-6 max-w-[1400px]">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold">Audit Log</h2>
        <span className="text-sm text-[var(--color-text-muted)]">{total} entries</span>
      </div>

      <div className="flex gap-3 mb-4">
        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)]"
        >
          <option value="">All Actions</option>
          <option value="update">Update</option>
          <option value="delete">Delete</option>
          <option value="bulk_update">Bulk Update</option>
        </select>
        <select
          value={entityFilter}
          onChange={(e) => { setEntityFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)]"
        >
          <option value="">All Entities</option>
          <option value="finding">Finding</option>
          <option value="quarantine">Quarantine</option>
        </select>
      </div>

      {query.isLoading && <div className="text-[var(--color-text-muted)]">Loading...</div>}

      {query.data && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-[var(--color-text-muted)] text-left">
                <th className="py-2 px-2">Timestamp</th>
                <th className="py-2 px-2">Action</th>
                <th className="py-2 px-2">Entity</th>
                <th className="py-2 px-2">Entity ID</th>
                <th className="py-2 px-2">Actor</th>
                <th className="py-2 px-2">Details</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr
                  key={e.id}
                  className="border-b border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] transition-colors"
                >
                  <td className="py-2 px-2 text-xs text-[var(--color-text-muted)]">
                    {formatTime(e.timestamp)}
                  </td>
                  <td className="py-2 px-2">
                    <span className="px-1.5 py-0.5 rounded text-xs font-medium bg-[var(--color-surface)] border border-[var(--color-border)]">
                      {e.action}
                    </span>
                  </td>
                  <td className="py-2 px-2 capitalize">{e.entity_type}</td>
                  <td className="py-2 px-2 font-mono text-xs">{e.entity_id}</td>
                  <td className="py-2 px-2 text-xs">{e.actor}</td>
                  <td className="py-2 px-2 text-xs text-[var(--color-text-muted)] max-w-xs truncate">
                    {e.details ?? "-"}
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