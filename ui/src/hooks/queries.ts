import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listFindings,
  getFinding,
  patchFinding,
  deleteFinding,
  bulkUpdateFindings,
  getFindingReport,
  listReports,
  getReport,
  countReports,
  listQuarantine,
  getQuarantine,
  deleteQuarantine,
  getStats,
  listAuditEntries,
  checkHealth,
  setToken,
  clearToken,
  type FindingFilters,
  type PatchFinding,
  type BulkUpdateRequest,
  type AuditFilters,
  type ReportListParams,
} from "@/api";

export function useFindings(filters: FindingFilters) {
  return useQuery({
    queryKey: ["findings", filters],
    queryFn: () => listFindings(filters),
  });
}

export function useFinding(id: number) {
  return useQuery({
    queryKey: ["finding", id],
    queryFn: () => getFinding(id),
    enabled: id > 0,
  });
}

export function usePatchFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: number; patch: PatchFinding }) =>
      patchFinding(id, patch),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });
}

export function useDeleteFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => deleteFinding(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });
}

export function useBulkUpdateFindings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkUpdateRequest) => bulkUpdateFindings(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });
}

export function useFindingReport(id: number) {
  return useQuery({
    queryKey: ["finding-report", id],
    queryFn: () => getFindingReport(id),
    enabled: id > 0,
  });
}

export function useReports(params?: ReportListParams) {
  return useQuery({
    queryKey: ["reports", params],
    queryFn: () => listReports(params),
  });
}

export function useReport(id: number) {
  return useQuery({
    queryKey: ["report", id],
    queryFn: () => getReport(id),
    enabled: id > 0,
  });
}

export function useReportCount(params?: ReportListParams) {
  return useQuery({
    queryKey: ["reports-count", params],
    queryFn: () => countReports(params as Record<string, unknown> | undefined),
  });
}

export function useQuarantineList(params?: Record<string, unknown>) {
  return useQuery({
    queryKey: ["quarantine", params],
    queryFn: () => listQuarantine(params),
  });
}

export function useQuarantineDetail(id: number) {
  return useQuery({
    queryKey: ["quarantine", id],
    queryFn: () => getQuarantine(id),
    enabled: id > 0,
  });
}

export function useDeleteQuarantine() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => deleteQuarantine(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["quarantine"] }),
  });
}

export function useStats() {
  return useQuery({
    queryKey: ["stats"],
    queryFn: getStats,
    refetchInterval: 30_000,
  });
}

export function useAuditLog(filters: AuditFilters) {
  return useQuery({
    queryKey: ["audit", filters],
    queryFn: () => listAuditEntries(filters),
  });
}

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: checkHealth,
    refetchInterval: 60_000,
  });
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ token }: { token: string }) => {
      setToken(token);
      const r = await checkHealth();
      if (r.status !== "ok") {
        clearToken();
        throw new Error("Health check failed");
      }
    },
    onSuccess: () => qc.invalidateQueries(),
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return () => {
    clearToken();
    qc.clear();
  };
}