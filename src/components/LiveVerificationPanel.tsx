import React from "react";
import { Globe, Mail, ShieldAlert, CheckCircle2, HelpCircle } from "lucide-react";
import { EmailEnrichment, UrlEnrichment } from "../lib/types";

interface LiveVerificationPanelProps {
  isLoading: boolean;
  emails: string[];
  urls: string[];
  emailResults: EmailEnrichment[];
  urlResults: UrlEnrichment[];
}

export const LiveVerificationPanel: React.FC<LiveVerificationPanelProps> = ({
  isLoading,
  emails,
  urls,
  emailResults,
  urlResults,
}) => {
  const totalTargets = emails.length + urls.length;

  return (
    <section className={`case-card ${isLoading ? "dashed-border" : ""}`}>
      <div className="section-label">
        05 — Live Threat-Intel Verification ({totalTargets} targets detected)
      </div>

      {totalTargets === 0 ? (
        <div style={{ fontSize: "13px", color: "var(--text-dim)", fontStyle: "italic", padding: "8px 0" }}>
          No external email addresses or URLs found in submitted text.
        </div>
      ) : (
        <div className="enrichment-table">
          {/* Email targets */}
          {emails.map((email) => {
            const data = emailResults.find((e) => e.email === email);

            return (
              <div key={email} className="enrichment-row">
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <Mail size={14} style={{ color: "var(--text-dim)" }} />
                  <span className="enrichment-target">{email}</span>
                </div>

                <div className="enrichment-status">
                  {isLoading ? (
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--text-dim)" }}>
                      <div className="spinner" />
                      <span>querying threat registries…</span>
                    </div>
                  ) : data?.virustotalRateLimited && !data.emailrep && !data.whois ? (
                    <span className="enrichment-status" style={{ color: "var(--text-dim)" }} title="VirusTotal free tier: 4 requests/minute">
                      <HelpCircle size={13} />
                      <span>VirusTotal: rate limited (4 req/min free tier) — try again shortly</span>
                    </span>
                  ) : !data || data.error ? (
                    <span className="enrichment-status unavailable" title="No threat intel keys configured or server offline">
                      <HelpCircle size={13} />
                      <span>enrichment unavailable</span>
                    </span>
                  ) : data.virustotal && data.virustotal.maliciousVotes > 0 ? (
                    <span style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                      <span className="enrichment-status suspicious">
                        <ShieldAlert size={14} />
                        <span>VirusTotal: {data.virustotal.maliciousVotes} vendors flag this domain ■</span>
                      </span>
                      {data.virustotal.flaggedBy && data.virustotal.flaggedBy.length > 0 && (
                        <span style={{ fontSize: "11px", color: "var(--text-dim)", paddingLeft: "20px" }}>
                          Flagged by: {data.virustotal.flaggedBy.join(", ")}
                        </span>
                      )}
                    </span>
                  ) : data.emailrep?.suspicious || data.emailrep?.disposable || data.disify?.disposable ? (
                    <span className="enrichment-status suspicious">
                      <ShieldAlert size={14} />
                      <span>
                        {data.emailrep?.disposable || data.disify?.disposable
                          ? "disposable email provider ■"
                          : "suspicious reputation match ■"}
                      </span>
                    </span>
                  ) : data.whois?.domainAgeDays != null ? (
                    <span className="enrichment-status verified">
                      <CheckCircle2 size={14} />
                      <span>
                        {data.domain} — registered {data.whois.createdDate?.slice(0, 10)} ({data.whois.domainAgeDays.toLocaleString()} days old) ✓
                      </span>
                    </span>
                  ) : data.virustotal?.domainAgeDays != null ? (
                    <span className="enrichment-status verified">
                      <CheckCircle2 size={14} />
                      <span>
                        {data.domain} — registered {data.virustotal.creationDate?.slice(0, 10)} ({data.virustotal.domainAgeDays.toLocaleString()} days old, via VirusTotal) ✓
                      </span>
                    </span>
                  ) : (
                    <span className="enrichment-status verified">
                      <CheckCircle2 size={14} />
                      <span>
                        {data.domain} — deliverable, reputation {data.emailrep?.reputation || "neutral"} ✓
                      </span>
                    </span>
                  )}
                </div>
              </div>
            );
          })}

          {/* URL targets */}
          {urls.map((url) => {
            const data = urlResults.find((u) => u.url === url);

            return (
              <div key={url} className="enrichment-row">
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <Globe size={14} style={{ color: "var(--text-dim)" }} />
                  <span className="enrichment-target">{url}</span>
                </div>

                <div className="enrichment-status">
                  {isLoading ? (
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--text-dim)" }}>
                      <div className="spinner" />
                      <span>scanning SafeBrowsing & IPDB…</span>
                    </div>
                  ) : !data || data.error ? (
                    <span className="enrichment-status unavailable" title="No SafeBrowsing / AbuseIPDB keys configured">
                      <HelpCircle size={13} />
                      <span>enrichment unavailable</span>
                    </span>
                  ) : data.safeBrowsing?.threatMatch ? (
                    <span className="enrichment-status suspicious">
                      <ShieldAlert size={14} />
                      <span>Google Safe Browsing: THREAT DETECTED ■</span>
                    </span>
                  ) : data.virustotal?.status === "completed" && data.virustotal.maliciousVotes > 0 ? (
                    <span style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
                      <span className="enrichment-status suspicious">
                        <ShieldAlert size={14} />
                        <span>
                          VirusTotal: {data.virustotal.maliciousVotes}/{data.virustotal.totalEngines} vendors flag this URL as malicious ■
                        </span>
                      </span>
                      {data.virustotal.flaggedBy && data.virustotal.flaggedBy.length > 0 && (
                        <span style={{ fontSize: "11px", color: "var(--text-dim)", paddingLeft: "20px" }}>
                          Flagged by: {data.virustotal.flaggedBy.join(", ")}
                        </span>
                      )}
                    </span>
                  ) : data.abuseIpdb && data.abuseIpdb.abuseConfidenceScore > 20 ? (
                    <span className="enrichment-status suspicious">
                      <ShieldAlert size={14} />
                      <span>AbuseIPDB confidence: {data.abuseIpdb.abuseConfidenceScore}% ■</span>
                    </span>
                  ) : data.virustotal?.status === "queued" ? (
                    <span className="enrichment-status" style={{ color: "var(--text-dim)" }}>
                      <HelpCircle size={13} />
                      <span>VirusTotal: newly submitted, still analyzing — rerun the scan shortly for a verdict</span>
                    </span>
                  ) : data.virustotal?.status === "rate_limited" ? (
                    <span className="enrichment-status" style={{ color: "var(--text-dim)" }} title="VirusTotal free tier: 4 requests/minute">
                      <HelpCircle size={13} />
                      <span>VirusTotal: rate limited (4 req/min free tier) — try again shortly</span>
                    </span>
                  ) : (
                    <span className="enrichment-status verified">
                      <CheckCircle2 size={14} />
                      <span>No active blocklist or malware matches reported ✓</span>
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
};
