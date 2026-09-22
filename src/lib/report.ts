import { ScanResult } from "./types";
import { band, generateRecommendations } from "./scoring";

export function buildReportText(params: {
  caseId: string;
  scannedText: string;
  scanResult: ScanResult;
  timestamp?: string;
}): string {
  const { caseId, scannedText, scanResult, timestamp = new Date().toISOString() } = params;
  const riskBand = band(scanResult.score);
  const recs = generateRecommendations(scanResult.categories);

  const preview = scannedText.trim().slice(0, 400);

  const lines: string[] = [];
  lines.push("=================================================");
  lines.push("REDFLAG INSPECTOR — FORENSIC SCAN REPORT");
  lines.push("=================================================");
  lines.push(`Case ID:     ${caseId}`);
  lines.push(`Timestamp:   ${timestamp}`);
  lines.push(`Threat Index: ${scanResult.score}/100 [${riskBand.label.toUpperCase()}]`);
  lines.push(`Confidence:   ${scanResult.confidence.label} (${scanResult.confidence.note})`);
  lines.push("");

  lines.push("-------------------------------------------------");
  lines.push("SCORE BREAKDOWN");
  lines.push("-------------------------------------------------");
  if (scanResult.breakdown.length === 0) {
    lines.push("No weighted categories triggered points.");
  } else {
    for (const b of scanResult.breakdown) {
      lines.push(`• +${b.contribution} pts — ${b.name}`);
    }
  }
  lines.push("");

  lines.push("-------------------------------------------------");
  lines.push("TRIGGERED SIGNALS & EVIDENCE");
  lines.push("-------------------------------------------------");
  let totalSignals = 0;
  for (const cat of scanResult.categories) {
    if (cat.hits.length > 0) {
      lines.push(`\n[${cat.name.toUpperCase()}] (Weight ${cat.weight})`);
      for (const hit of cat.hits) {
        totalSignals++;
        const strength = hit.points >= 35 ? "STRONG SIGNAL" : "SUPPORTING SIGNAL";
        const srcTag = hit.source === "live" ? " [VERIFIED LIVE]" : "";
        lines.push(`  * ${hit.title} (${hit.points} pts, ${strength})${srcTag}`);
        lines.push(`    Explanation: ${hit.explanation}`);
        if (hit.evidence) {
          lines.push(`    Evidence: "${hit.evidence}"`);
        }
      }
    }
  }
  if (totalSignals === 0) {
    lines.push("No red flags or phishing indicators detected.");
  }
  lines.push("");

  lines.push("-------------------------------------------------");
  lines.push("RECOMMENDED ACTIONS");
  lines.push("-------------------------------------------------");
  for (const rec of recs) {
    lines.push(`[ ] ${rec}`);
  }
  lines.push("");

  lines.push("-------------------------------------------------");
  lines.push("SUBMITTED MATERIAL (FIRST 400 CHARACTERS)");
  lines.push("-------------------------------------------------");
  lines.push(preview + (scannedText.length > 400 ? "..." : ""));
  lines.push("=================================================");

  return lines.join("\n");
}
