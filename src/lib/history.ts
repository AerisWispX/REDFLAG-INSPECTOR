import { ScanHistoryEntry, RiskBandKey } from "./types";

const HISTORY_STORAGE_KEY = "redflag_scan_history";
const SEQ_PREFIX = "redflag_seq_";
const MAX_HISTORY = 20;

export function generateCaseId(date = new Date()): string {
  const yyyy = date.getFullYear();
  const mm = String(date.getMonth() + 1).padStart(2, "0");
  const dd = String(date.getDate()).padStart(2, "0");
  const dateKey = `${yyyy}${mm}${dd}`;

  const seqKey = `${SEQ_PREFIX}${dateKey}`;
  let currentSeq = 1;
  try {
    const stored = localStorage.getItem(seqKey);
    if (stored) {
      currentSeq = parseInt(stored, 10) + 1;
    }
    localStorage.setItem(seqKey, String(currentSeq));
  } catch {
    // If localStorage is unavailable or restricted
  }

  const seqStr = String(currentSeq).padStart(3, "0");
  return `CASE-${dateKey}-${seqStr}`;
}

export function loadHistory(): ScanHistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed;
    }
  } catch (err) {
    console.warn("Failed to load scan history:", err);
  }
  return [];
}

export function saveScanToHistory(entry: {
  caseId: string;
  score: number;
  bandKey: RiskBandKey;
  bandLabel: string;
  text: string;
}): ScanHistoryEntry[] {
  const preview = entry.text
    .trim()
    .replace(/[\r\n\s]+/g, " ")
    .slice(0, 60);

  const time = new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  const newEntry: ScanHistoryEntry = {
    caseId: entry.caseId,
    score: entry.score,
    bandKey: entry.bandKey,
    bandLabel: entry.bandLabel,
    preview: preview.length === 60 ? `${preview}...` : preview,
    fullText: entry.text,
    time,
  };

  const existing = loadHistory();
  const updated = [newEntry, ...existing.filter((e) => e.caseId !== entry.caseId)].slice(
    0,
    MAX_HISTORY
  );

  try {
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(updated));
  } catch (err) {
    console.warn("Failed to save scan history to localStorage:", err);
  }

  return updated;
}

export function clearAllData(): void {
  try {
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith("redflag_")) {
        keysToRemove.push(key);
      }
    }
    for (const key of keysToRemove) {
      localStorage.removeItem(key);
    }
  } catch (err) {
    console.warn("Failed to clear localStorage keys:", err);
  }
}
