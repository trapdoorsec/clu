import { useReport } from "@/hooks/queries";
import { useParams, Link } from "react-router-dom";
import { formatTime, severityColor, severityLabel, cn } from "@/lib/utils";

export default function ReportDetailPage() {
  const { id } = useParams<{ id: string }>();
  const numId = Number(id) || 0;
  const query = useReport(numId);

  if (query.isLoading) {
    return <div className="p-8 text-[var(--color-text-dim)]">Loading report...</div>;
  }
  if (query.error || !query.data) {
    return <div className="p-8 text-[var(--color-danger)]">Report not found</div>;
  }

  const r = query.data;

  return (
    <div className="p-8 max-w-4xl">
      <Link
        to="/reports"
        className="text-sm text-[var(--color-text-dim)] hover:text-[var(--color-primary)] transition-colors"
      >
        &larr; Back to reports
      </Link>

      <div className="mt-5 p-6 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
        <div className="flex justify-between items-start mb-5">
          <div>
            <h2 className="text-xl font-bold font-mono tracking-tight">{r.package_name}</h2>
            {r.package_version && (
              <span className="text-sm text-[var(--color-text-dim)] ml-2">
                v{r.package_version}
              </span>
            )}
          </div>
          <span className={cn("px-2.5 py-1 rounded-md text-sm font-medium border", severityColor(r.severity))}>
            {r.severity} {severityLabel(r.severity)}
          </span>
        </div>

        <div className="grid grid-cols-3 gap-5 text-sm mb-5">
          <div>
            <div className="text-[10px] uppercase tracking-[0.15em] text-[var(--color-text-dim)] mb-1">Ecosystem</div>
            <div className="capitalize text-[var(--color-text)]">{r.ecosystem}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-[0.15em] text-[var(--color-text-dim)] mb-1">Recommendation</div>
            <div className="text-[var(--color-text)]">{r.recommendation}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-[0.15em] text-[var(--color-text-dim)] mb-1">Malicious</div>
            <div className={r.is_malicious ? "text-[var(--color-danger)]" : "text-[var(--color-success)]"}>
              {r.is_malicious ? "Yes" : "No"}
            </div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-[0.15em] text-[var(--color-text-dim)] mb-1">Timestamp</div>
            <div className="text-[var(--color-text)]">{formatTime(r.timestamp)}</div>
          </div>
          <div className="col-span-2">
            <div className="text-[10px] uppercase tracking-[0.15em] text-[var(--color-text-dim)] mb-1">SHA256</div>
            <div className="font-mono text-xs text-[var(--color-text-muted)] break-all">{r.sha256}</div>
          </div>
        </div>

        {r.heuristic_matches && Array.isArray(r.heuristic_matches) && r.heuristic_matches.length > 0 && (
          <div className="mt-5">
            <h3 className="text-xs uppercase tracking-[0.15em] font-semibold text-[var(--color-text-dim)] mb-2">Heuristic Matches</h3>
            <pre className="bg-[var(--color-bg)] p-4 rounded-lg text-xs overflow-x-auto border border-[var(--color-border)] text-[var(--color-text-muted)]">
              {JSON.stringify(r.heuristic_matches, null, 2)}
            </pre>
          </div>
        )}

        {r.typosquat_matches && Array.isArray(r.typosquat_matches) && r.typosquat_matches.length > 0 && (
          <div className="mt-5">
            <h3 className="text-xs uppercase tracking-[0.15em] font-semibold text-[var(--color-text-dim)] mb-2">Typosquat Matches</h3>
            <pre className="bg-[var(--color-bg)] p-4 rounded-lg text-xs overflow-x-auto border border-[var(--color-border)] text-[var(--color-text-muted)]">
              {JSON.stringify(r.typosquat_matches, null, 2)}
            </pre>
          </div>
        )}

        {r.yara_result ? (
          <div className="mt-5">
            <h3 className="text-xs uppercase tracking-[0.15em] font-semibold text-[var(--color-text-dim)] mb-2">YARA Result</h3>
            <pre className="bg-[var(--color-bg)] p-4 rounded-lg text-xs overflow-x-auto border border-[var(--color-border)] text-[var(--color-text-muted)]">
              {JSON.stringify(r.yara_result, null, 2)}
            </pre>
          </div>
        ) : null}

        {r.llm_analysis ? (
          <div className="mt-5">
            <h3 className="text-xs uppercase tracking-[0.15em] font-semibold text-[var(--color-text-dim)] mb-2">LLM Analysis</h3>
            <pre className="bg-[var(--color-bg)] p-4 rounded-lg text-xs overflow-x-auto border border-[var(--color-border)] text-[var(--color-text-muted)]">
              {JSON.stringify(r.llm_analysis, null, 2)}
            </pre>
          </div>
        ) : null}
      </div>
    </div>
  );
}