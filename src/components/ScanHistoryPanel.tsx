import React from "react";
import { Trash2, ShieldCheck, History, ArrowUpRight } from "lucide-react";
import { ScanHistoryEntry } from "../lib/types";

interface ScanHistoryPanelProps {
  history: ScanHistoryEntry[];
  onClearHistory: () => void;
  onSelectEntry?: (entry: ScanHistoryEntry) => void;
}

export const ScanHistoryPanel: React.FC<ScanHistoryPanelProps> = ({
  history,
  onClearHistory,
  onSelectEntry,
}) => {
  const getBandBadgeClass = (bandKey: string) => {
    switch (bandKey) {
      case "crit":
        return { color: "var(--crit)", bg: "var(--crit-bg)", border: "var(--crit)" };
      case "danger":
        return { color: "var(--danger)", bg: "var(--danger-bg)", border: "var(--danger)" };
      case "warn":
        return { color: "var(--warn)", bg: "var(--warn-bg)", border: "var(--warn)" };
      default:
        return { color: "var(--safe)", bg: "var(--safe-bg)", border: "var(--safe)" };
    }
  };

  return (
    <section className="case-card">
      <div className="section-label">
        <History size={13} style={{ color: "var(--accent)" }} />
        <span>06 — Local Scan History ({history.length}/20)</span>
      </div>

      {history.length === 0 ? (
        <div className="history-empty-message">
          <ShieldCheck size={24} style={{ color: "var(--safe)", margin: "0 auto 8px auto", display: "block" }} />
          <p><strong>Strict Privacy Guarantee:</strong> No scan logs or text submitted are ever transmitted to any remote server or database.</p>
          <p style={{ marginTop: "4px" }}>Scans are held strictly in your browser's private localStorage and capped at 20 recent records.</p>
        </div>
      ) : (
        <>
          {/* Desktop Table View */}
          <div className="history-table-container">
            <table className="history-table">
              <thead>
                <tr>
                  <th style={{ width: "150px" }}>Case ID</th>
                  <th style={{ width: "85px" }}>Index</th>
                  <th style={{ width: "105px" }}>Threat Band</th>
                  <th>Content Preview</th>
                  <th style={{ width: "95px", textAlign: "right" }}>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry) => {
                  const style = getBandBadgeClass(entry.bandKey);
                  return (
                    <tr
                      key={entry.caseId}
                      className={onSelectEntry ? "history-clickable-row" : ""}
                      onClick={() => onSelectEntry && onSelectEntry(entry)}
                      title={onSelectEntry ? "Click to view preview in inspector" : undefined}
                    >
                      <td style={{ fontWeight: 600 }}>{entry.caseId}</td>
                      <td>
                        <span className="tabular" style={{ fontWeight: 700, color: style.color }}>
                          {entry.score}/100
                        </span>
                      </td>
                      <td>
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: 700,
                            padding: "2px 6px",
                            borderRadius: "2px",
                            color: style.color,
                            backgroundColor: style.bg,
                            border: `1px solid ${style.border}`,
                            textTransform: "uppercase",
                          }}
                        >
                          {entry.bandLabel}
                        </span>
                      </td>
                      <td style={{ color: "var(--text-dim)", maxWidth: "260px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {entry.preview}
                      </td>
                      <td style={{ textAlign: "right", color: "var(--text-dim)", fontSize: "11px" }}>
                        {entry.time}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Mobile Card View (optimized for screens < 640px) */}
          <div className="history-mobile-list">
            {history.map((entry) => {
              const style = getBandBadgeClass(entry.bandKey);
              return (
                <div
                  key={entry.caseId}
                  className="history-mobile-card"
                  onClick={() => onSelectEntry && onSelectEntry(entry)}
                >
                  <div className="history-mobile-card-top">
                    <span className="history-mobile-caseid mono">{entry.caseId}</span>
                    <span
                      style={{
                        fontSize: "10px",
                        fontWeight: 700,
                        padding: "2px 6px",
                        borderRadius: "2px",
                        color: style.color,
                        backgroundColor: style.bg,
                        border: `1px solid ${style.border}`,
                        textTransform: "uppercase",
                      }}
                    >
                      {entry.score} • {entry.bandLabel}
                    </span>
                  </div>
                  <p className="history-mobile-preview">{entry.preview}</p>
                  <div className="history-mobile-card-bottom">
                    <span className="history-mobile-time mono">{entry.time}</span>
                    {onSelectEntry && (
                      <span className="history-mobile-load-hint">
                        <span>inspect</span>
                        <ArrowUpRight size={11} />
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}

      <div className="history-footer">
        <span className="privacy-notice">
          All data is client-side only. Scans are never logged or stored remotely.
        </span>

        {history.length > 0 && (
          <button
            type="button"
            className="clear-data-btn"
            onClick={onClearHistory}
            title="Wipe all local scan history and sequence counters"
          >
            <span style={{ display: "inline-flex", alignItems: "center", gap: "5px" }}>
              <Trash2 size={12} />
              Clear all history
            </span>
          </button>
        )}
      </div>
    </section>
  );
};
