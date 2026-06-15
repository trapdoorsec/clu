export interface Finding {
  id: number;
  report_id: number | null;
  ecosystem: string;
  name: string;
  version: string | null;
  sha256: string | null;
  first_seen: string;
  last_updated: string;
  status: FindingStatus;
  severity: number;
  classification: string | null;
  score: number;
  ioc: string | null;
  payload_excerpt: string | null;
  analyst_notes: string | null;
  reported_to: string | null;
}

export type FindingStatus =
  | "new"
  | "triaging"
  | "confirmed_malicious"
  | "benign"
  | "reported"
  | "duplicate";

export interface FindingsResponse {
  items: Finding[];
  total: number;
  offset: number;
  limit: number;
}

export interface FindingFilters {
  ecosystem?: string;
  status?: FindingStatus;
  name?: string;
  min_severity?: number;
  min_score?: number;
  since?: string;
  limit?: number;
  offset?: number;
}

export interface PatchFinding {
  status?: FindingStatus;
  classification?: string;
  analyst_notes?: string;
  reported_to?: string;
}

export interface BulkUpdateRequest {
  ids: number[];
  status?: FindingStatus;
  classification?: string;
  analyst_notes?: string;
  reported_to?: string;
}

export interface BulkUpdateResponse {
  updated: number[];
  failed: [number, string][];
}

export interface ReportListParams {
  limit?: number;
  offset?: number;
  ecosystem?: string;
  malicious?: boolean;
  min_severity?: number;
  sort_by?: string;
  sort_order?: string;
}

export interface QuarantinedPackage {
  id: number;
  package_name: string;
  package_version: string | null;
  ecosystem: string;
  severity: number;
  recommendation: string;
  archive_size: number | null;
  quarantined_at: string;
  report_id: number | null;
}

export interface QuarantineDetail extends QuarantinedPackage {
  archive_path: string;
  metadata_path: string | null;
  report: ReportDetail | null;
}

export interface QuarantineListResponse {
  items: QuarantinedPackage[];
  total: number;
  offset: number;
  limit: number;
}

export interface ReportDetail {
  id: number;
  package_name: string;
  package_version: string | null;
  timestamp: string;
  ecosystem: string;
  sha256: string;
  heuristic_matches: unknown[];
  typosquat_matches: unknown[];
  yara_result: unknown | null;
  injection_detection: unknown | null;
  llm_analysis: unknown | null;
  severity: number;
  is_malicious: boolean;
  recommendation: string;
}

export interface ReportListResponse {
  items: ReportDetail[];
  total: number;
  offset: number;
  limit: number;
}

export interface StatsResponse {
  total_findings: number;
  total_reports: number;
  total_quarantined: number;
  findings_by_severity: Record<string, number>;
  findings_by_status: Record<string, number>;
  findings_by_ecosystem: Record<string, number>;
  recent_findings_24h: number;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  action: string;
  entity_type: string;
  entity_id: number;
  old_value: string | null;
  new_value: string | null;
  details: string | null;
  actor: string;
}

export interface AuditListResponse {
  entries: AuditEntry[];
  total: number;
}

export interface AuditFilters {
  action?: string;
  entity_type?: string;
  entity_id?: number;
  since?: string;
  limit?: number;
  offset?: number;
}

export interface YaraRule {
  name: string;
  severity: string;
  description: string;
  ecosystem: string;
  risk_score: number;
  enabled: boolean;
  source: string;
}

export interface YaraRulesListResponse {
  rules: YaraRule[];
  total: number;
}

export interface CreateRuleRequest {
  name: string;
  content: string;
}

export interface TestRuleRequest {
  content: string;
  test_data: string;
}

export interface TestRuleResponse {
  matched_rules: string[];
}