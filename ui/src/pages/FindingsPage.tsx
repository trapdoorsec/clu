import { useState } from "react";
import { useFindings, usePatchFinding, useBulkUpdateFindings } from "@/hooks/queries";
import { severityColor, severityLabel, statusLabel, statusColor, formatTime, cn } from "@/lib/utils";
import type { FindingStatus } from "@/api";

const PAGE_SIZE = 50;
const STATUS_OPTIONS: FindingStatus[] = [
  "new",
  "triaging",
  "confirmed_malicious",
  "benign",
  "reported",
  "duplicate",
];

export default function FindingsPage() {
  const [page, setPage] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [ecosystemFilter, setEcosystemFilter] = useState<string>("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Set<number>>(new Set());

  const query = useFindings({
    status: statusFilter as FindingStatus | undefined,
    ecosystem: ecosystemFilter || undefined,
    name: search || undefined,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  });

  const patchMutation = usePatchFinding();
  const bulkMutation = useBulkUpdateFindings();

  function toggleSelect(id: number) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (!query.data) return;
    if (selected.size === query.data.items.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(query.data.items.map((f) => f.id)));
    }
  }

  async function handleStatusChange(id: number, status: FindingStatus) {
    await patchMutation.mutateAsync({ id, patch: { status } });
  }

  async function handleBulkStatus(status: FindingStatus) {
    if (selected.size === 0) return;
    await bulkMutation.mutateAsync({ ids: Array.from(selected), status });
    setSelected(new Set());
  }

  const findings = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="p-6 max-w-[1400px]">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold">Findings</h2>
        <span className="text-sm text-[var(--color-text-muted)]">{total} total</span>
      </div>

      <div className="flex gap-3 mb-4 flex-wrap">
        <input
          type="text"
          placeholder="Search name..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm placeholder-[var(--color-text-muted)] focus:outline-none focus:border-[var(--color-primary)]"
        />
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)]"
        >
          <option value="">All Statuses</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{statusLabel(s)}</option>
          ))}
        </select>
        <select
          value={ecosystemFilter}
          onChange={(e) => { setEcosystemFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)]"
        >
          <option value="">All Ecosystems</option>
          <option value="pypi">PyPI</option>
          <option value="npm">npm</option>
        </select>

        {selected.size > 0 && (
          <div className="flex gap-2 ml-auto items-center">
            <span className="text-sm text-[var(--color-text-muted)]">{selected.size} selected</span>
            {STATUS_OPTIONS.map((s) => (
              <button
                key={s}
                onClick={() => handleBulkStatus(s)}
                className="px-2 py-1 text-xs rounded border border-[var(--color-border)] bg-[var(--color-surface)] hover:bg-[var(--color-surface-hover)] transition-colors"
              >
                Set {statusLabel(s)}
              </button>
            ))}
          </div>
        )}
      </div>

      {query.isLoading && <div className="text-[var(--color-text-muted)]">Loading...</div>}
      {query.error && <div className="text-[var(--color-danger)]">Error loading findings</div>}

      {query.data && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-[var(--color-text-muted)] text-left">
                <th className="py-2 px-2 w-8">
                  <input
                    type="checkbox"
                    checked={selected.size === findings.length && findings.length > 0}
                    onChange={toggleAll}
                    className="rounded"
                  />
                </th>
                <th className="py-2 px-2">Name</th>
                <th className="py-2 px-2">Ecosystem</th>
                <th className="py-2 px-2">Severity</th>
                <th className="py-2 px-2">Status</th>
                <th className="py-2 px-2">First Seen</th>
                <th className="py-2 px-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr
                  key={f.id}
                  className="border-b border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] transition-colors"
                >
                  <td className="py-2 px-2">
                    <input
                      type="checkbox"
                      checked={selected.has(f.id)}
                      onChange={() => toggleSelect(f.id)}
                      className="rounded"
                    />
                  </td>
                  <td className="py-2 px-2 font-mono">
                    {f.name}
                    {f.version && <span className="text-[var(--color-text-muted)] ml-1">v{f.version}</span>}
                  </td>
                  <td className="py-2 px-2 capitalize">{f.ecosystem}</td>
                  <td className="py-2 px-2">
                    <span className={cn("px-1.5 py-0.5 rounded text-xs font-medium border", severityColor(f.severity))}>
                      {f.severity} {severityLabel(f.severity)}
                    </span>
                  </td>
                  <td className="py-2 px-2">
                    <span className={cn("px-1.5 py-0.5 rounded text-xs font-medium", statusColor(f.status))}>
                      {statusLabel(f.status)}
                    </span>
                  </td>
                  <td className="py-2 px-2 text-xs text-[var(--color-text-muted)]">
                    {formatTime(f.first_seen)}
                  </td>
                  <td className="py-2 px-2">
                    <select
                      value={f.status}
                      onChange={(e) => handleStatusChange(f.id, e.target.value as FindingStatus)}
                      className="rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-1.5 py-0.5 text-xs"
                    >
                      {STATUS_OPTIONS.map((s) => (
                        <option key={s} value={s}>{statusLabel(s)}</option>
                      ))}
                    </select>
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