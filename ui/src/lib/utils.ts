import { clsx, type ClassValue } from "clsx";

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function severityColor(severity: number): string {
  if (severity >= 20) return "text-red-400 bg-red-400/10 border-red-400/30";
  if (severity >= 13) return "text-orange-400 bg-orange-400/10 border-orange-400/30";
  if (severity >= 5) return "text-yellow-400 bg-yellow-400/10 border-yellow-400/30";
  return "text-green-400 bg-green-400/10 border-green-400/30";
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
    new: "text-blue-400 bg-blue-400/10",
    triaging: "text-yellow-400 bg-yellow-400/10",
    confirmed_malicious: "text-red-400 bg-red-400/10",
    benign: "text-green-400 bg-green-400/10",
    reported: "text-purple-400 bg-purple-400/10",
    duplicate: "text-gray-400 bg-gray-400/10",
  };
  return m[status] ?? "text-gray-400 bg-gray-400/10";
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