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
    <div className="p-8 max-w-[1400px]">
      <div className="flex justify-between items-end mb-6">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Findings</h2>
          <p className="text-sm text-[var(--color-text-dim)] mt-1">{total} total findings</p>
        </div>
      </div>

      <div className="flex gap-3 mb-5 flex-wrap">
        <input
          type="text"
          placeholder="Search name..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm placeholder-[var(--color-text-dim)] focus:outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]/20 transition-all duration-150"
        />
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)] transition-all duration-150"
        >
          <option value="">All Statuses</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{statusLabel(s)}</option>
          ))}
        </select>
        <select
          value={ecosystemFilter}
          onChange={(e) => { setEcosystemFilter(e.target.value); setPage(0); }}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-sm text-[var(--color-text)] focus:outline-none focus:border-[var(--color-primary)] transition-all duration-150"
        >
          <option value="">All Ecosystems</option>
          <option value="pypi">PyPI</option>
          <option value="npm">npm</option>
        </select>

        {selected.size > 0 && (
          <div className="flex gap-2 ml-auto items-center">
            <span className="text-xs text-[var(--color-text-dim)]">{selected.size} selected</span>
            {STATUS_OPTIONS.map((s) => (
              <button
                key={s}
                onClick={() => handleBulkStatus(s)}
                className="px-2.5 py-1 text-xs rounded border border-[var(--color-border)] bg-[var(--color-surface)] hover:bg-[var(--color-surface-hover)] hover:border-[var(--color-border-light)] transition-all duration-150"
              >
                Set {statusLabel(s)}
              </button>
            ))}
          </div>
        )}
      </div>

      {query.isLoading && <div className="text-[var(--color-text-dim)]">Loading...</div>}
      {query.error && <div className="text-[var(--color-danger)]">Error loading findings</div>}

      {query.data && (
        <div className="overflow-x-auto rounded-xl border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-[var(--color-text-dim)] text-left text-xs uppercase tracking-wider">
                <th className="py-3 px-4 w-8">
                  <input
                    type="checkbox"
                    checked={selected.size === findings.length && findings.length > 0}
                    onChange={toggleAll}
                    className="rounded accent-[var(--color-primary)]"
                  />
                </th>
                <th className="py-3 px-4 font-medium">Name</th>
                <th className="py-3 px-4 font-medium">Ecosystem</th>
                <th className="py-3 px-4 font-medium">Severity</th>
                <th className="py-3 px-4 font-medium">Status</th>
                <th className="py-3 px-4 font-medium">First Seen</th>
                <th className="py-3 px-4 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr
                  key={f.id}
                  className="border-b border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] transition-colors duration-100"
                >
                  <td className="py-2.5 px-4">
                    <input
                      type="checkbox"
                      checked={selected.has(f.id)}
                      onChange={() => toggleSelect(f.id)}
                      className="rounded accent-[var(--color-primary)]"
                    />
                  </td>
                  <td className="py-2.5 px-4 font-mono text-[var(--color-text)]">
                    {f.name}
                    {f.version && <span className="text-[var(--color-text-dim)] ml-1">v{f.version}</span>}
                  </td>
                  <td className="py-2.5 px-4 capitalize text-[var(--color-text-muted)]">{f.ecosystem}</td>
                  <td className="py-2.5 px-4">
                    <span className={cn("px-2 py-0.5 rounded text-xs font-medium border", severityColor(f.severity))}>
                      {f.severity} {severityLabel(f.severity)}
                    </span>
                  </td>
                  <td className="py-2.5 px-4">
                    <span className={cn("px-2 py-0.5 rounded text-xs font-medium", statusColor(f.status))}>
                      {statusLabel(f.status)}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-xs text-[var(--color-text-dim)]">
                    {formatTime(f.first_seen)}
                  </td>
                  <td className="py-2.5 px-4">
                    <select
                      value={f.status}
                      onChange={(e) => handleStatusChange(f.id, e.target.value as FindingStatus)}
                      className="rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-1.5 py-0.5 text-xs focus:outline-none focus:border-[var(--color-primary)] transition-colors"
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