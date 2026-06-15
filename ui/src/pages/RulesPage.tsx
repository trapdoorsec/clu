import { useState } from "react";
import { useYaraRules, useToggleYaraRule, useDeleteYaraRule, useCreateYaraRule, useTestYaraRule } from "@/hooks/queries";

function severityBadge(severity: string): { bg: string; text: string } {
  switch (severity.toLowerCase()) {
    case "critical":
      return { bg: "bg-red-500/20", text: "text-red-400" };
    case "high":
      return { bg: "bg-orange-500/20", text: "text-orange-400" };
    case "medium":
      return { bg: "bg-yellow-500/20", text: "text-yellow-400" };
    case "low":
      return { bg: "bg-green-500/20", text: "text-green-400" };
    default:
      return { bg: "bg-gray-500/20", text: "text-gray-400" };
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

  if (isLoading) return <div className="p-8">Loading rules...</div>;
  if (error) return <div className="p-8 text-red-400">Error: {error.message}</div>;

  const rules = data?.rules ?? [];
  const builtinRules = rules.filter((r) => r.source === "builtin");
  const customRules = rules.filter((r) => r.source === "custom");

  return (
    <div className="p-8 max-w-5xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">YARA Rules</h1>
          <p className="text-sm text-[var(--color-text-muted)] mt-1">
            {data?.total ?? 0} rules loaded
          </p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-4 py-2 bg-[var(--color-primary)] text-white rounded hover:opacity-90 text-sm font-medium"
        >
          {showCreate ? "Cancel" : "New Rule"}
        </button>
      </div>

      {showCreate && (
        <div className="mb-6 border border-[var(--color-border)] rounded-lg p-4 bg-[var(--color-surface)]">
          <h2 className="text-lg font-semibold mb-3">Create Custom Rule</h2>
          <div className="space-y-3">
            <div>
              <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                Rule Name
              </label>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded text-sm"
                placeholder="e.g. my_custom_rule"
              />
            </div>
            <div>
              <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                YARA Rule Content
              </label>
              <textarea
                value={newContent}
                onChange={(e) => setNewContent(e.target.value)}
                className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded text-sm font-mono"
                rows={8}
                placeholder={`rule my_rule {\n  meta:\n    severity = "high"\n    description = "My custom rule"\n    ecosystem = "pypi"\n  strings:\n    $s = "suspicious_string"\n  condition:\n    $s\n}`}
              />
            </div>
            <div>
              <label className="block text-sm text-[var(--color-text-muted)] mb-1">
                Test Data (optional)
              </label>
              <textarea
                value={testData}
                onChange={(e) => setTestData(e.target.value)}
                className="w-full px-3 py-2 bg-[var(--color-bg)] border border-[var(--color-border)] rounded text-sm font-mono"
                rows={3}
                placeholder="Sample text to test the rule against"
              />
            </div>
            {testResult !== null && (
              <div className="p-3 bg-green-900/20 border border-green-700/30 rounded text-sm">
                <span className="font-medium text-green-400">Matched rules:</span>{" "}
                {testResult.length > 0 ? testResult.join(", ") : "No matches"}
              </div>
            )}
            {testError && (
              <div className="p-3 bg-red-900/20 border border-red-700/30 rounded text-sm text-red-400">
                {testError}
              </div>
            )}
            <div className="flex gap-2">
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
                className="px-4 py-2 bg-[var(--color-primary)] text-white rounded hover:opacity-90 text-sm font-medium disabled:opacity-50"
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
                  className="px-4 py-2 border border-[var(--color-border)] rounded text-sm hover:bg-[var(--color-surface-hover)] disabled:opacity-50"
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
          <h2 className="text-lg font-semibold mb-3">Custom Rules</h2>
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

      <h2 className="text-lg font-semibold mb-3">Built-in Rules</h2>
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
      className={`flex items-center gap-3 p-3 border border-[var(--color-border)] rounded bg-[var(--color-surface)] ${
        !rule.enabled ? "opacity-50" : ""
      }`}
    >
      <button
        onClick={() => onToggle(!rule.enabled)}
        className={`w-10 h-5 rounded-full relative transition-colors ${
          rule.enabled ? "bg-[var(--color-primary)]" : "bg-gray-600"
        }`}
        title={rule.enabled ? "Disable rule" : "Enable rule"}
      >
        <span
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
            rule.enabled ? "translate-x-5" : ""
          }`}
        />
      </button>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-medium">{rule.name}</span>
          <span
            className={`px-1.5 py-0.5 rounded text-xs ${badge.bg} ${badge.text}`}
          >
            {rule.severity}
          </span>
          {rule.ecosystem !== "all" && (
            <span className="px-1.5 py-0.5 rounded text-xs bg-blue-500/20 text-blue-400">
              {rule.ecosystem}
            </span>
          )}
        </div>
        <p className="text-xs text-[var(--color-text-muted)] truncate">
          {rule.description}
        </p>
      </div>

      <span className="text-xs text-[var(--color-text-muted)] tabular-nums">
        risk: {rule.risk_score}
      </span>

      {onDelete && rule.source === "custom" && (
        <button
          onClick={onDelete}
          className="text-red-400 hover:text-red-300 text-xs px-2 py-1 border border-red-800/30 rounded hover:bg-red-900/20"
        >
          Delete
        </button>
      )}
    </div>
  );
}