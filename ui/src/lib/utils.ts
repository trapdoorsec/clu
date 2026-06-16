import { clsx, type ClassValue } from "clsx";

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function severityColor(severity: number): string {
  if (severity >= 20) return "text-red-400 bg-red-500/10 border-red-500/20";
  if (severity >= 13) return "text-orange-400 bg-orange-500/10 border-orange-500/20";
  if (severity >= 5) return "text-[var(--color-warning)] bg-[var(--color-warning)]/10 border-[var(--color-warning)]/20";
  return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
}

export function severityLabel(severity: number): string {
  if (severity >= 20) return "CRITICAL";
  if (severity >= 13) return "HIGH";
  if (severity >= 5) return "MEDIUM";
  return "LOW";
}

export function statusLabel(status: string): string {
  const m: Record<string, string> = {
    new: "New",
    triaging: "Triaging",
    confirmed_malicious: "Confirmed",
    benign: "Benign",
    reported: "Reported",
    duplicate: "Duplicate",
  };
  return m[status] ?? status;
}

export function statusColor(status: string): string {
  const m: Record<string, string> = {
    new: "text-sky-400 bg-sky-500/10",
    triaging: "text-[var(--color-warning)] bg-[var(--color-warning)]/10",
    confirmed_malicious: "text-red-400 bg-red-500/10",
    benign: "text-emerald-400 bg-emerald-500/10",
    reported: "text-[var(--color-primary)] bg-[var(--color-primary-ghost)]",
    duplicate: "text-gray-400 bg-gray-500/10",
  };
  return m[status] ?? "text-gray-400 bg-gray-500/10";
}

export function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + "..." : s;
}