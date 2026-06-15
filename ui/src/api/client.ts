import type {
  Finding,
  FindingFilters,
  FindingsResponse,
  PatchFinding,
  BulkUpdateRequest,
  BulkUpdateResponse,
  QuarantineListResponse,
  QuarantineDetail,
  ReportDetail,
  ReportListResponse,
  StatsResponse,
  AuditListResponse,
  AuditFilters,
  YaraRulesListResponse,
  YaraRule,
  CreateRuleRequest,
  TestRuleRequest,
  TestRuleResponse,
} from "./types";

const BASE = "";

async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const token = localStorage.getItem("clu_token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string> | undefined),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    throw new ApiError(401, "Unauthorized");
  }
  if (res.status === 204) {
    return undefined as T;
  }
  if (!res.ok) {
    const body = await res.text();
    throw new ApiError(res.status, body || res.statusText);
  }
  return res.json();
}

export class ApiError extends Error {
  status: number;
  constructor(
    status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function qs(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") {
      sp.set(k, String(v));
    }
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

// ── Findings ────────────────────────────────────────────────────────

export async function listFindings(
  filters: FindingFilters
): Promise<FindingsResponse> {
  return request(`/api/findings${qs(filters as Record<string, unknown>)}`);
}

export async function getFinding(id: number): Promise<Finding> {
  return request(`/api/findings/${id}`);
}

export async function patchFinding(
  id: number,
  patch: PatchFinding
): Promise<Finding> {
  return request(`/api/findings/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export async function deleteFinding(id: number): Promise<void> {
  return request(`/api/findings/${id}`, { method: "DELETE" });
}

export async function bulkUpdateFindings(
  body: BulkUpdateRequest
): Promise<BulkUpdateResponse> {
  return request(`/api/findings/bulk`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function getFindingReport(
  id: number
): Promise<Record<string, unknown>> {
  return request(`/api/findings/${id}/report`);
}

// ── Reports ─────────────────────────────────────────────────────────

export interface ReportListParams {
  limit?: number;
  offset?: number;
  ecosystem?: string;
  malicious?: boolean;
  min_severity?: number;
  sort_by?: string;
  sort_order?: string;
}

export async function listReports(
  params?: ReportListParams
): Promise<ReportListResponse> {
  return request(`/api/reports${qs(params as Record<string, unknown> ?? {})}`);
}

export async function getReport(id: number): Promise<ReportDetail> {
  return request(`/api/reports/${id}`);
}

export async function countReports(params?: {
  ecosystem?: string;
  malicious?: boolean;
  min_severity?: number;
}): Promise<{ count: number }> {
  return request(`/api/reports/count${qs(params ?? {})}`);
}

// ── Quarantine ───────────────────────────────────────────────────────

export async function listQuarantine(params?: {
  ecosystem?: string;
  package_name?: string;
  min_severity?: number;
  since?: string;
  limit?: number;
  offset?: number;
}): Promise<QuarantineListResponse> {
  return request(`/api/quarantine${qs(params ?? {})}`);
}

export async function getQuarantine(id: number): Promise<QuarantineDetail> {
  return request(`/api/quarantine/${id}`);
}

export async function deleteQuarantine(id: number): Promise<void> {
  return request(`/api/quarantine/${id}`, { method: "DELETE" });
}

export function quarantineArchiveUrl(id: number): string {
  const token = localStorage.getItem("clu_token");
  const url = `/api/quarantine/${id}/archive`;
  return token ? `${url}?token=${encodeURIComponent(token)}` : url;
}

// ── Stats ───────────────────────────────────────────────────────────

export async function getStats(): Promise<StatsResponse> {
  return request("/api/stats");
}

// ── Audit ───────────────────────────────────────────────────────────

export async function listAuditEntries(
  filters: AuditFilters
): Promise<AuditListResponse> {
  return request(`/api/audit-log${qs(filters as Record<string, unknown>)}`);
}

// ── YARA Rules ─────────────────────────────────────────────────────

export async function listYaraRules(): Promise<YaraRulesListResponse> {
  return request("/api/rules");
}

export async function getYaraRule(name: string): Promise<YaraRule> {
  return request(`/api/rules/${encodeURIComponent(name)}`);
}

export async function createYaraRule(
  body: CreateRuleRequest
): Promise<YaraRule> {
  return request("/api/rules", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function deleteYaraRule(name: string): Promise<void> {
  return request(`/api/rules/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
}

export async function setYaraRuleEnabled(
  name: string,
  enabled: boolean
): Promise<YaraRule> {
  return request(
    `/api/rules/${encodeURIComponent(name)}/enable`,
    {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    }
  );
}

export async function testYaraRule(
  body: TestRuleRequest
): Promise<TestRuleResponse> {
  return request("/api/rules/test", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// ── Health ───────────────────────────────────────────────────────────

export async function checkHealth(): Promise<{ status: string; db: string }> {
  return request("/healthz");
}

// ── Auth ────────────────────────────────────────────────────────────

export function setToken(token: string): void {
  localStorage.setItem("clu_token", token);
}

export function getToken(): string | null {
  return localStorage.getItem("clu_token");
}

export function clearToken(): void {
  localStorage.removeItem("clu_token");
}

export function isAuthenticated(): boolean {
  return !!getToken();
}