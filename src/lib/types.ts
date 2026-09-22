export interface Rule {
  id: string;
  title: string;
  explanation: string;
  pattern: RegExp;
  points: number;
}

export interface CategoryHit {
  title: string;
  explanation: string;
  evidence: string | null;
  points: number;
  source: "heuristic" | "live";
}

export interface CategoryResult {
  id: string;
  name: string;
  description: string;
  weight: number;
  hits: CategoryHit[];
}

export interface ScoreBreakdownLine {
  name: string;
  contribution: number;
}

export interface Confidence {
  label: "Low" | "Medium" | "High";
  note: string;
}

export interface ScanResult {
  score: number;
  categories: CategoryResult[];
  breakdown: ScoreBreakdownLine[];
  confidence: Confidence;
  doNotItems: string[];
}

export interface ScanHistoryEntry {
  caseId: string;
  score: number;
  bandKey: "safe" | "warn" | "danger" | "crit";
  bandLabel: string;
  preview: string;
  fullText?: string;
  time: string;
}

export interface EmailEnrichment {
  email: string;
  domain: string;
  emailrep?: {
    reputation: string;
    suspicious: boolean;
    newDomain: boolean;
    daysSinceDomainCreation: number | null;
    freeProvider: boolean;
    disposable: boolean;
    credentialsLeaked: boolean;
  };
  disify?: {
    disposable: boolean;
    dnsValid: boolean;
  };
  whois?: {
    createdDate: string | null;
    domainAgeDays: number | null;
  };
  virustotal?: {
    reputation: number;
    maliciousVotes: number;
    creationDate: string | null;
    domainAgeDays: number | null;
    flaggedBy?: string[];
  };
  virustotalRateLimited?: boolean;
  error?: string;
}

export interface UrlEnrichment {
  url: string;
  isIp: boolean;
  safeBrowsing?: {
    threatMatch: boolean;
    threatTypes: string[];
  };
  abuseIpdb?: {
    abuseConfidenceScore: number;
  } | null;
  virustotal?: {
    status: "completed" | "queued" | "rate_limited";
    maliciousVotes: number;
    suspiciousVotes: number;
    totalEngines: number;
    permalink: string;
    flaggedBy?: string[];
  };
  error?: string;
}

// The model's read of the whole message. This is an OPINION, not a
// verifiable fact like a Safe Browsing/VirusTotal match — kept as its own
// type, its own section in the UI, and deliberately excluded from the
// score-floor / forceSevere mechanics that verified-live signals get. See
// applyLiveEnrichment() in scoring.ts for exactly how it's bounded.
export interface AiAnalysis {
  verdict: "scam" | "suspicious" | "legitimate" | "uncertain";
  confidence: "low" | "medium" | "high";
  scoreAdjustment: number; // clamped to [-10, 15] by the server before this ever reaches the client
  reasoning: string;
  languageDetected: string;
  promptInjectionAttempt: boolean;
  model: string;
  error?: string;
  rateLimited?: boolean;
}

export interface EnrichResponse {
  emails: EmailEnrichment[];
  urls: UrlEnrichment[];
  aiAnalysis?: AiAnalysis;
}

export type RiskBandKey = "safe" | "warn" | "danger" | "crit";

export interface RiskBand {
  key: RiskBandKey;
  label: "Low" | "Moderate" | "High" | "Severe";
  minScore: number;
  colorVar: string;
  bgVar: string;
}

// Community reporting (section 08). Persisted server-side in a JSON file
// (api/reportsStore.ts) — the first piece of this app's data that is NOT
// per-browser localStorage or in-process-only, because it's inherently
// cross-user: other people need to see it. Only what's needed to make a
// report useful to a stranger is stored; the full scanned text never is —
// same 400-char-preview privacy posture as the "copy report" feature.
export interface ScamReport {
  id: string;
  createdAt: string;
  category: "job_offer" | "rental_listing" | "other";
  domain: string | null;
  urlOrEmail: string | null;
  textPreview: string;
  score: number;
  bandLabel: string;
  note: string;
  confirmCount: number;
  status: "pending" | "verified" | "removed";
}

// What the client sends to create one — server fills in id/createdAt/status/confirmCount.
export interface ScamReportInput {
  category: ScamReport["category"];
  domain: string | null;
  urlOrEmail: string | null;
  textPreview: string;
  score: number;
  bandLabel: string;
  note: string;
}
