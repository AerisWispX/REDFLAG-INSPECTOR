import React, { useState } from "react";
import { Copy, Check, AlertCircle, Link2 } from "lucide-react";
import { CategoryResult, ScanResult } from "../lib/types";
import { generateRecommendations } from "../lib/scoring";
import { buildReportText } from "../lib/report";
import { encodeShareLink } from "../lib/share";

interface RecommendationsProps {
  categories: CategoryResult[];
  caseId: string;
  scannedText: string;
  scanResult: ScanResult;
}

export const Recommendations: React.FC<RecommendationsProps> = ({
  categories,
  caseId,
  scannedText,
  scanResult,
}) => {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const [shared, setShared] = useState(false);
  const [shareError, setShareError] = useState(false);

  const handleShareReport = async () => {
    try {
      const link = encodeShareLink({
        caseId,
        timestamp: new Date().toISOString(),
        scannedTextPreview: scannedText.trim().slice(0, 400),
        scanResult,
      });
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(link);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = link;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      setShared(true);
      setShareError(false);
      setTimeout(() => setShared(false), 3000);
    } catch (err) {
      console.error("Share link failed:", err);
      setShareError(true);
      setTimeout(() => setShareError(false), 4000);
    }
  };

  const recommendations = generateRecommendations(categories);

  const handleCopyReport = async () => {
    try {
      const fullReport = buildReportText({
        caseId,
        scannedText,
        scanResult,
      });

      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(fullReport);
        setCopied(true);
        setCopyError(false);
        setTimeout(() => setCopied(false), 3000);
      } else {
        // Fallback for environments lacking clipboard API permissions
        const textarea = document.createElement("textarea");
        textarea.value = fullReport;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
        setCopied(true);
        setTimeout(() => setCopied(false), 3000);
      }
    } catch (err) {
      console.error("Clipboard copy failed:", err);
      setCopyError(true);
      setTimeout(() => setCopyError(false), 4000);
    }
  };

  return (
    <section className="case-card">
      <div className="section-label">04 — Recommended Actions</div>

      <div className="recommendations-list">
        {recommendations.map((rec, idx) => (
          <div key={idx} className="rec-item">
            <span className="rec-bullet">[{idx + 1}]</span>
            <span>{rec}</span>
          </div>
        ))}
      </div>

      <div className="report-action-footer">
        {copied && (
          <span className="copied-toast">
            <Check size={14} />
            <span>✓ Copied full forensic report to clipboard</span>
          </span>
        )}

        {copyError && (
          <span style={{ fontSize: "12px", color: "var(--danger)", display: "inline-flex", alignItems: "center", gap: "4px" }}>
            <AlertCircle size={14} />
            <span>Clipboard unavailable. Please select and copy manually.</span>
          </span>
        )}

        {shared && (
          <span className="copied-toast">
            <Check size={14} />
            <span>✓ Shareable link copied — the report is encoded in the link itself, nothing is stored on a server</span>
          </span>
        )}

        {shareError && (
          <span style={{ fontSize: "12px", color: "var(--danger)", display: "inline-flex", alignItems: "center", gap: "4px" }}>
            <AlertCircle size={14} />
            <span>Could not build a share link. Please try again.</span>
          </span>
        )}

        <button
          type="button"
          className="copy-report-btn"
          onClick={handleShareReport}
          title="Copies a link that encodes this entire report — no server storage, nothing else is sent"
        >
          <Link2 size={13} />
          <span>Share Report</span>
        </button>

        <button
          type="button"
          className="copy-report-btn"
          onClick={handleCopyReport}
        >
          <Copy size={13} />
          <span>Copy Case Report</span>
        </button>
      </div>
    </section>
  );
};
