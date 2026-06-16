import { useState } from "react";
import { useYaraRules, useToggleYaraRule, useDeleteYaraRule, useCreateYaraRule, useTestYaraRule } from "@/hooks/queries";

function severityBadge(severity: string): { bg: string; text: string } {
  switch (severity.toLowerCase()) {
    case "critical":
      return { bg: "bg-red-500/12", text: "text-red-400" };
    case "high":
      return { bg: "bg-orange-500/12", text: "text-orange-400" };
    case "medium":
      return { bg: "bg-[var(--color-warning)]/12", text: "text-[var(--color-warning)]" };
    case "low":
      return { bg: "bg-emerald-500/12", text: "text-emerald-400" };
    default:
      return { bg: "bg-gray-500/12", text: "text-gray-400" };
  }
}

export default function RulesPage() {
  const { data, isLoading, error } = useYaraRules();
  const toggleRule = useToggleYaraRule();
  const deleteRule = useDeleteYaraRule();
  const createRule = useCreateYaraRule();
  const testRule = useTestYaraRule();

  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newContent, setNewContent] = useState("");
  const [testData, setTestData] = useState("");
  const [testResult, setTestResult] = useState<string[] | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  if (isLoading) return <div className="p-8 text-[var(--color-text-dim)]">Loading rules...</div>;
  if (error) return <div className="p-8 text-[var(--color-danger)]">Error: {error.message}</div>;

  const rules = data?.rules ?? [];
  const builtinRules = rules.filter((r) => r.source === "builtin");
  const customRules = rules.filter((r) => r.source === "custom");

  return (
    <div className="p-8 max-w-5xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">YARA Rules</h1>
          <p className="text-sm text-[var(--color-text-dim)] mt-1">
            {data?.total ?? 0} rules loaded
          </p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-4 py-2 bg-[var(--color-primary)] text-black rounded-lg text-sm font-semibold hover:bg-[var(--color-primary-hover)] transition-colors duration-150"
        >
          {showCreate ? "Cancel" : "New Rule"}
        </button>
      </div>

      {showCreate && (
        <div className="mb-6 border border-[var(--color-border)] rounded-xl p-5 bg-[var(--color-surface)]">
          <h2 className="text-lg font-semibold mb-4">Create Custom Rule</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-xs uppercase tracking-wider text-[var(--color-text-dim)] mb-1.5 font-medium">
                Rule Name
              </label>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg text-sm focus:outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]/20 transition-all duration-150"
                placeholder="e.g. my_custom_rule"
              />
            </div>
            <div>
              <label className="block text-xs uppercase tracking-wider text-[var(--color-text-dim)] mb-1.5 font-medium">
                YARA Rule Content
              </label>
              <textarea
                value={newContent}
                onChange={(e) => setNewContent(e.target.value)}
                className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg text-sm font-mono focus:outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]/20 transition-all duration-150"
                rows={8}
                placeholder={`rule my_rule {\n  meta:\n    severity = "high"\n    description = "My custom rule"\n    ecosystem = "pypi"\n  strings:\n    $s = "suspicious_string"\n  condition:\n    $s\n}`}
              />
            </div>
            <div>
              <label className="block text-xs uppercase tracking-wider text-[var(--color-text-dim)] mb-1.5 font-medium">
                Test Data (optional)
              </label>
              <textarea
                value={testData}
                onChange={(e) => setTestData(e.target.value)}
                className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded-lg text-sm font-mono focus:outline-none focus:border-[var(--color-primary)] focus:ring-1 focus:ring-[var(--color-primary)]/20 transition-all duration-150"
                rows={3}
                placeholder="Sample text to test the rule against"
              />
            </div>
            {testResult !== null && (
              <div className="p-3 bg-emerald-500/8 border border-emerald-600/20 rounded-lg text-sm">
                <span className="font-medium text-emerald-400">Matched rules:</span>{" "}
                {testResult.length > 0 ? testResult.join(", ") : "No matches"}
              </div>
            )}
            {testError && (
              <div className="p-3 bg-[var(--color-danger-dim)] border border-red-700/20 rounded-lg text-sm text-red-400">
                {testError}
              </div>
            )}
            <div className="flex gap-3">
              <button
                onClick={() => {
                  if (!newName || !newContent) return;
                  createRule.mutate(
                    { name: newName, content: newContent },
                    {
                      onSuccess: () => {
                        setNewName("");
                        setNewContent("");
                        setShowCreate(false);
                      },
                      onError: (err) => setTestError(err.message),
                    }
                  );
                }}
                disabled={!newName || !newContent || createRule.isPending}
                className="px-4 py-2 bg-[var(--color-primary)] text-black rounded-lg text-sm font-semibold hover:bg-[var(--color-primary-hover)] disabled:opacity-40 transition-colors duration-150"
              >
                Create Rule
              </button>
              {newContent && testData && (
                <button
                  onClick={() => {
                    setTestResult(null);
                    setTestError(null);
                    testRule.mutate(
                      { content: newContent, test_data: testData },
                      {
                        onSuccess: (res) => setTestResult(res.matched_rules),
                        onError: (err) => setTestError(err.message),
                      }
                    );
                  }}
                  disabled={testRule.isPending}
                  className="px-4 py-2 border border-[var(--color-border)] rounded-lg text-sm hover:bg-[var(--color-surface-hover)] hover:border-[var(--color-border-light)] disabled:opacity-40 transition-all duration-150"
                >
                  Test Rule
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {customRules.length > 0 && (
        <>
          <h2 className="text-sm uppercase tracking-[0.15em] font-semibold text-[var(--color-text-dim)] mb-3">Custom Rules</h2>
          <div className="space-y-2 mb-8">
            {customRules.map((rule) => (
              <RuleRow
                key={rule.name}
                rule={rule}
                onToggle={(enabled) =>
                  toggleRule.mutate({ name: rule.name, enabled })
                }
                onDelete={() => deleteRule.mutate(rule.name)}
              />
            ))}
          </div>
        </>
      )}

      <h2 className="text-sm uppercase tracking-[0.15em] font-semibold text-[var(--color-text-dim)] mb-3">Built-in Rules</h2>
      <div className="space-y-2">
        {builtinRules.map((rule) => (
          <RuleRow
            key={rule.name}
            rule={rule}
            onToggle={(enabled) =>
              toggleRule.mutate({ name: rule.name, enabled })
            }
          />
        ))}
      </div>
    </div>
  );
}

function RuleRow({
  rule,
  onToggle,
  onDelete,
}: {
  rule: {
    name: string;
    severity: string;
    description: string;
    ecosystem: string;
    risk_score: number;
    enabled: boolean;
    source: string;
  };
  onToggle: (enabled: boolean) => void;
  onDelete?: () => void;
}) {
  const badge = severityBadge(rule.severity);

  return (
    <div
      className={`flex items-center gap-3 p-3.5 border border-[var(--color-border)] rounded-lg bg-[var(--color-surface)] transition-all duration-150 ${
        !rule.enabled ? "opacity-40" : ""
      }`}
    >
      <button
        onClick={() => onToggle(!rule.enabled)}
        className={`w-9 h-5 rounded-full relative transition-colors duration-200 shrink-0 ${
          rule.enabled ? "bg-[var(--color-primary)]" : "bg-[var(--color-border-light)]"
        }`}
        title={rule.enabled ? "Disable rule" : "Enable rule"}
      >
        <span
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-black transition-transform duration-200 ${
            rule.enabled ? "translate-x-4" : ""
          }`}
        />
      </button>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-medium text-[var(--color-text)]">{rule.name}</span>
          <span
            className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider ${badge.bg} ${badge.text}`}
          >
            {rule.severity}
          </span>
          {rule.ecosystem !== "all" && (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-sky-500/12 text-sky-400 uppercase tracking-wider">
              {rule.ecosystem}
            </span>
          )}
        </div>
        <p className="text-xs text-[var(--color-text-dim)] truncate mt-0.5">
          {rule.description}
        </p>
      </div>

      <span className="text-[11px] text-[var(--color-text-dim)] tabular-nums font-mono">
        risk: {rule.risk_score}
      </span>

      {onDelete && rule.source === "custom" && (
        <button
          onClick={onDelete}
          className="text-[var(--color-danger)] hover:text-red-300 text-xs px-2 py-1 border border-[var(--color-danger)]/20 rounded-md hover:bg-[var(--color-danger-dim)] transition-all duration-150"
        >
          Delete
        </button>
      )}
    </div>
  );
}