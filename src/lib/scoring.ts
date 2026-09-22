import { CATEGORIES } from "./rules";
import { extractEmails, extractUrls } from "./extract";
import { checkTyposquatBatch } from "./typosquat";
import {
  CategoryHit,
  CategoryResult,
  Confidence,
  EnrichResponse,
  RiskBand,
  ScanResult,
  ScoreBreakdownLine,
} from "./types";

function domainOfEmail(email: string): string {
  return email.split("@")[1] || "";
}
function domainOfUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** Runs the offline typosquat check against every domain found in the text (emails + URL hosts). */
function detectImpersonationHits(text: string): CategoryHit[] {
  const domains = [
    ...extractEmails(text).map(domainOfEmail),
    ...extractUrls(text).map(domainOfUrl),
  ].filter(Boolean);
  const matches = checkTyposquatBatch(domains);
  return matches.map((m) => ({
    title: `Domain "${m.domain}" closely resembles "${m.brand}"`,
    explanation: `This domain differs from the real ${m.brand} by only ${m.distance} character${
      m.distance > 1 ? "s" : ""
    } — a classic typosquat used to impersonate a trusted employer or platform, run entirely offline against a list of commonly-impersonated brands.`,
    evidence: m.domain,
    points: m.distance === 1 ? 60 : 40,
    source: "heuristic" as const,
  }));
}

export function band(score: number, forceSevere = false): RiskBand {
  if (forceSevere || score >= 75) {
    return {
      key: "crit",
      label: "Severe",
      minScore: 75,
      colorVar: "--crit",
      bgVar: "--crit-bg",
    };
  }
  if (score >= 45) {
    return {
      key: "danger",
      label: "High",
      minScore: 45,
      colorVar: "--danger",
      bgVar: "--danger-bg",
    };
  }
  if (score >= 18) {
    return {
      key: "warn",
      label: "Moderate",
      minScore: 18,
      colorVar: "--warn",
      bgVar: "--warn-bg",
    };
  }
  return {
    key: "safe",
    label: "Low",
    minScore: 0,
    colorVar: "--safe",
    bgVar: "--safe-bg",
  };
}

export function extractEvidence(text: string, pattern: RegExp): string | null {
  const flags = pattern.flags.replace("g", "");
  const regex = new RegExp(pattern.source, flags);
  const match = regex.exec(text);
  if (!match || match.index === undefined) return null;

  const matchStart = match.index;
  const matchEnd = matchStart + match[0].length;
  const contextChars = 28;

  const start = Math.max(0, matchStart - contextChars);
  const end = Math.min(text.length, matchEnd + contextChars);

  let snippet = text.slice(start, end).replace(/[\r\n\t]+/g, " ");
  if (start > 0) {
    snippet = "..." + snippet.trimStart();
  }
  if (end < text.length) {
    snippet = snippet.trimEnd() + "...";
  }
  return snippet;
}

export function confidenceLevel(categoriesWithHitsCount: number): Confidence {
  if (categoriesWithHitsCount >= 4) {
    return {
      label: "High",
      note: `${categoriesWithHitsCount} independent signal categories fired`,
    };
  }
  if (categoriesWithHitsCount >= 2) {
    return {
      label: "Medium",
      note: `${categoriesWithHitsCount} independent signal categories fired`,
    };
  }
  if (categoriesWithHitsCount === 1) {
    return {
      label: "Low",
      note: "1 independent signal category fired",
    };
  }
  return {
    label: "Low",
    note: "0 independent signal categories fired",
  };
}

export function doNotItems(categories: CategoryResult[]): string[] {
  const items: string[] = [];

  const paymentCat = categories.find((c) => c.id === "payment");
  const credentialCat = categories.find((c) => c.id === "credential");
  const linkCat = categories.find((c) => c.id === "link");

  if (paymentCat && paymentCat.hits.length > 0) {
    items.push("DO NOT PAY");
  }
  if (credentialCat && credentialCat.hits.length > 0) {
    items.push("DO NOT SHARE IDS, PASSWORDS, OR BANK LOGIN DETAILS");
  }
  if (linkCat && linkCat.hits.length > 0) {
    items.push("DO NOT CLICK ANY LINKS");
  }

  // Fallback to reach up to 3 items if fewer than 3 apply
  const fallback = "DO NOT MOVE THE CONVERSATION OFF OFFICIAL CHANNELS";
  if (items.length < 3 && !items.includes(fallback)) {
    items.push(fallback);
  }

  return items.slice(0, 3);
}

export function generateRecommendations(categories: CategoryResult[]): string[] {
  const recs: string[] = [];

  const hasHits = (id: string) => {
    const cat = categories.find((c) => c.id === id);
    return !!(cat && cat.hits.length > 0);
  };

  if (hasHits("payment")) {
    recs.push("Do not send money, wire deposits, or pay onboarding or equipment fees upfront.");
  }
  if (hasHits("credential")) {
    recs.push("Do not share government IDs, SSN, driver license scans, or banking passwords.");
  }
  if (hasHits("channel")) {
    recs.push("Re-verify communication via official employer or property management directories.");
  }
  if (hasHits("urgency")) {
    recs.push("Slow down: artificial countdowns and same-day payment demands are coercion tactics.");
  }
  if (hasHits("link")) {
    recs.push("Do not click shortened, unencrypted (HTTP), or unfamiliar external links.");
  }
  if (hasHits("impersonation")) {
    recs.push("Navigate to the real company's site by typing its known address yourself — do not trust this domain, even if it looks close.");
  }

  if (recs.length === 0) {
    recs.push("No immediate red flags detected; continue following standard online verification procedures.");
  }

  // Always end with platform reporting recommendation
  recs.push("Report this message or listing to the platform, job portal, or email provider it arrived through.");
  return recs;
}

export function scanText(text: string): ScanResult {
  const categoryResults: CategoryResult[] = [];
  let overall = 0;
  let floor = 0;
  let categoriesWithHits = 0;

  // Computed once, outside the per-category loop, since it isn't derived
  // from a category's regex rules like everything else here — see
  // detectImpersonationHits() above.
  const impersonationHits = detectImpersonationHits(text);

  for (const catDef of CATEGORIES) {
    const hits: CategoryHit[] = [];
    let raw = 0;

    for (const rule of catDef.rules) {
      if (rule.pattern.test(text)) {
        const evidence = extractEvidence(text, rule.pattern);
        raw += rule.points;
        hits.push({
          title: rule.title,
          explanation: rule.explanation,
          evidence,
          points: rule.points,
          source: "heuristic",
        });
      }
    }

    if (catDef.id === "impersonation") {
      for (const h of impersonationHits) {
        hits.push(h);
        raw += h.points;
      }
    }

    if (raw >= 70) {
      floor = Math.max(floor, 55);
    }

    if (hits.length > 0) {
      categoriesWithHits++;
    }

    const capped = Math.min(100, raw);
    const contribution = (capped * catDef.weight) / 100;
    overall += contribution;

    categoryResults.push({
      id: catDef.id,
      name: catDef.name,
      description: catDef.description,
      weight: catDef.weight,
      hits,
    });
  }

  const finalScore = Math.round(Math.min(100, Math.max(overall, floor)));

  // Generate score breakdown lines
  const breakdown: ScoreBreakdownLine[] = [];
  for (const cat of categoryResults) {
    const raw = cat.hits.reduce((acc, h) => acc + h.points, 0);
    const capped = Math.min(100, raw);
    const contrib = Math.round((capped * cat.weight) / 100);
    if (contrib > 0) {
      breakdown.push({
        name: cat.name,
        contribution: contrib,
      });
    }
  }
  breakdown.sort((a, b) => b.contribution - a.contribution);

  const confidence = confidenceLevel(categoriesWithHits);
  const doNots = doNotItems(categoryResults);

  return {
    score: finalScore,
    categories: categoryResults,
    breakdown,
    confidence,
    doNotItems: doNots,
  };
}

export function applyLiveEnrichment(
  baseResult: ScanResult,
  enrichment: EnrichResponse
): { result: ScanResult; forceSevere: boolean } {
  // Clone category results
  const updatedCategories: CategoryResult[] = baseResult.categories.map((c) => ({
    ...c,
    hits: [...c.hits],
  }));

  let forceSevere = false;

  const getCat = (id: string) => updatedCategories.find((c) => c.id === id);

  // 1. Email enrichments
  for (const emailData of enrichment.emails || []) {
    const { emailrep, disify, whois, virustotal } = emailData;

    // Domain age < 90 or new domain -> identity, 40 pts. WHOIS is the most
    // direct source; EmailRep and VirusTotal both cross-check the same
    // signal independently, so any one of the three can trigger this.
    const daysOld = emailrep?.daysSinceDomainCreation ?? whois?.domainAgeDays ?? virustotal?.domainAgeDays;
    if (emailrep?.newDomain === true || (daysOld != null && daysOld < 90)) {
      const daysText = daysOld != null ? `${daysOld}` : "recently";
      getCat("identity")?.hits.push({
        title: `Sender domain registered ${daysText} days ago`,
        explanation: "Newly registered domains are frequently used for disposable phishing and fraud campaigns.",
        evidence: emailData.domain,
        points: 40,
        source: "live",
      });
    }

    // Disposable email -> channel, 35 pts
    if (emailrep?.disposable === true || disify?.disposable === true) {
      getCat("channel")?.hits.push({
        title: "Disposable / temporary email address",
        explanation: "The sender used an ephemeral, disposable mail service designed to hide true identity.",
        evidence: emailData.email,
        points: 35,
        source: "live",
      });
    }

    // Credentials leaked -> identity, 20 pts
    if (emailrep?.credentialsLeaked === true) {
      getCat("identity")?.hits.push({
        title: "This email appears in known credential leaks",
        explanation: "The sender address has been exposed in publicly indexed breach databases.",
        evidence: emailData.email,
        points: 20,
        source: "live",
      });
    }

    // VirusTotal: security vendors actively flag this domain -> identity, 35 pts
    if (virustotal && (virustotal.maliciousVotes > 0 || virustotal.reputation < -10)) {
      getCat("identity")?.hits.push({
        title: `VirusTotal: ${virustotal.maliciousVotes} security vendor${virustotal.maliciousVotes === 1 ? "" : "s"} flag this domain as malicious`,
        explanation: "Independent confirmation from VirusTotal's aggregated antivirus/security-vendor engines, not a pattern match.",
        evidence: emailData.domain,
        points: 35,
        source: "live",
      });
    }
  }

  // 2. URL enrichments
  for (const urlData of enrichment.urls || []) {
    // SafeBrowsing threat match -> force Severe + link, 100 pts
    if (urlData.safeBrowsing?.threatMatch === true) {
      forceSevere = true;
      getCat("link")?.hits.push({
        title: "Google Safe Browsing threat match detected",
        explanation: `Identified as active threat: ${(urlData.safeBrowsing.threatTypes || ["MALWARE/PHISHING"]).join(", ")}.`,
        evidence: urlData.url,
        points: 100,
        source: "live",
      });
    }

    // AbuseIPDB score > 50 -> link, 40 pts
    if (urlData.abuseIpdb && urlData.abuseIpdb.abuseConfidenceScore > 50) {
      getCat("link")?.hits.push({
        title: `IP has a ${urlData.abuseIpdb.abuseConfidenceScore}% abuse confidence score on AbuseIPDB`,
        explanation: "The destination server has recorded reports of malicious attacks or credential harvesting.",
        evidence: urlData.url,
        points: 40,
        source: "live",
      });
    }

    // VirusTotal: 3+ engines flag it -> force Severe, same standing as a Safe
    // Browsing match. 1-2 engines is treated as a strong-but-not-forcing
    // signal, since a couple of aggressive/noisy engines alone are a common
    // false-positive source on multi-engine aggregators.
    if (urlData.virustotal?.status === "completed" && urlData.virustotal.maliciousVotes > 0) {
      const { maliciousVotes, suspiciousVotes, totalEngines } = urlData.virustotal;
      if (maliciousVotes >= 3) forceSevere = true;
      getCat("link")?.hits.push({
        title: `VirusTotal: ${maliciousVotes}/${totalEngines} security vendors flag this URL as malicious${suspiciousVotes ? ` (+${suspiciousVotes} suspicious)` : ""}`,
        explanation: "Independent confirmation from VirusTotal's aggregated antivirus/security-vendor engines, not a pattern match.",
        evidence: urlData.url,
        points: maliciousVotes >= 3 ? 100 : 45,
        source: "live",
      });
    }
  }

  // Recompute score
  let overall = 0;
  let floor = 0;
  let categoriesWithHits = 0;

  for (const cat of updatedCategories) {
    const raw = cat.hits.reduce((acc, h) => acc + h.points, 0);
    if (raw >= 70) floor = Math.max(floor, 55);
    if (cat.hits.length > 0) categoriesWithHits++;

    const capped = Math.min(100, raw);
    const contribution = (capped * cat.weight) / 100;
    overall += contribution;
  }

  // AI Analysis (Groq): an OPINION, not a verified fact, so it's bounded
  // and applied differently from every other live signal above:
  //  - It nudges `overall` (the category-derived score) by at most ±10/+15
  //    (already clamped server-side; re-clamped here defensively), applied
  //    BEFORE the floor is taken — so a strong negative AI read can soften
  //    a borderline heuristic score, but can never pull the total below an
  //    active hard floor from a genuinely severe category (the floor is
  //    still `Math.max(overall + aiAdjustment, floor)` below).
  //  - It NEVER sets forceSevere. Only an independently-verifiable match
  //    (Safe Browsing, 3+ VirusTotal engines) can force that band
  //    unconditionally; the AI can at most tip an already-elevated score
  //    over a threshold, never manufacture Severe from a clean message.
  const aiAdjustment = enrichment.aiAnalysis?.error || enrichment.aiAnalysis?.rateLimited
    ? 0
    : Math.max(-10, Math.min(15, enrichment.aiAnalysis?.scoreAdjustment ?? 0));
  overall += aiAdjustment;

  let finalScore = Math.round(Math.min(100, Math.max(overall, floor)));
  if (forceSevere && finalScore < 75) {
    finalScore = 75; // Severe threshold
  }

  const breakdown: ScoreBreakdownLine[] = [];
  for (const cat of updatedCategories) {
    const raw = cat.hits.reduce((acc, h) => acc + h.points, 0);
    const capped = Math.min(100, raw);
    const contrib = Math.round((capped * cat.weight) / 100);
    if (contrib > 0) {
      breakdown.push({
        name: cat.name,
        contribution: contrib,
      });
    }
  }
  breakdown.sort((a, b) => b.contribution - a.contribution);

  const confidence = confidenceLevel(categoriesWithHits);
  const doNots = doNotItems(updatedCategories);

  return {
    result: {
      score: finalScore,
      categories: updatedCategories,
      breakdown,
      confidence,
      doNotItems: doNots,
    },
    forceSevere,
  };
}
