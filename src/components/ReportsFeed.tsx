import React, { useEffect, useState } from "react";
import { ThumbsUp, ShieldCheck, Clock } from "lucide-react";
import { ScamReport } from "../lib/types";
import { fetchReports, confirmReport } from "../lib/reports";

const CATEGORY_LABEL: Record<ScamReport["category"], string> = {
  job_offer: "Job Offer Scam",
  rental_listing: "Rental Listing Scam",
  other: "Other",
};

function bandColorFor(bandLabel: string): string {
  switch (bandLabel) {
    case "Severe":
      return "var(--crit)";
    case "High":
      return "var(--danger)";
    case "Moderate":
      return "var(--warn)";
    default:
      return "var(--safe)";
  }
}

function timeAgo(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export const ReportsFeed: React.FC = () => {
  const [reports, setReports] = useState<ScamReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [confirmingIds, setConfirmingIds] = useState<Set<string>>(new Set());
  const [confirmedIds, setConfirmedIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    fetchReports()
      .then(setReports)
      .finally(() => setLoading(false));
  }, []);

  const handleConfirm = async (id: string) => {
    if (confirmedIds.has(id) || confirmingIds.has(id)) return; // client-side dedupe UX; server also rate-limits
    setConfirmingIds((prev) => new Set(prev).add(id));
    const { report } = await confirmReport(id);
    if (report) {
      setReports((prev) => prev.map((r) => (r.id === id ? report : r)));
      setConfirmedIds((prev) => new Set(prev).add(id));
    }
    setConfirmingIds((prev) => {
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
  };

  return (
    <>
      <section className="case-card">
        <div className="section-label">Community Reports</div>
        <p className="section-note">
          Scams other people have reported after scanning them. Anyone can confirm a report they recognize —
          reports with more confirmations, and any an operator has manually verified, are shown first. This feed
          is public and stored server-side (not just in your browser); see the report form for exactly what's
          shared.
        </p>
      </section>

      {loading ? (
        <div className="loading-row">
          <div className="spinner" />
          <span>Loading reports…</span>
        </div>
      ) : reports.length === 0 ? (
        <section className="case-card">
          <p className="empty-state">
            No reports yet. Scan a message on the Scanner tab and use "Report This Scam" to add the first one.
          </p>
        </section>
      ) : (
        reports.map((r) => (
          <div key={r.id} className="report-card">
            <div className="report-card-top">
              <span className="report-badge category">{CATEGORY_LABEL[r.category]}</span>
              {r.status === "verified" && (
                <span className="report-badge verified">
                  <ShieldCheck size={11} className="icon-inline" />
                  Verified by operator
                </span>
              )}
              <span className="report-score" style={{ color: bandColorFor(r.bandLabel) }}>
                {r.score}/100 · {r.bandLabel}
              </span>
              <span className="report-meta push-right meta-with-icon">
                <Clock size={11} />
                {timeAgo(r.createdAt)}
              </span>
            </div>

            {r.domain && <div className="report-meta">Domain/contact: {r.domain}</div>}

            <div className="report-preview">"{r.textPreview}"</div>

            {r.note && <div className="report-note">Reporter's note: {r.note}</div>}

            <div className="report-card-footer">
              <button
                type="button"
                className="confirm-btn"
                onClick={() => handleConfirm(r.id)}
                disabled={confirmedIds.has(r.id) || confirmingIds.has(r.id)}
              >
                <ThumbsUp size={12} />
                <span>
                  {confirmedIds.has(r.id) ? "Confirmed" : "I can confirm this"} ({r.confirmCount})
                </span>
              </button>
            </div>
          </div>
        ))
      )}
    </>
  );
};
