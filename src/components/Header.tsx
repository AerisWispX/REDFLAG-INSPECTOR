import React from "react";
import { ShieldAlert, Sun, Moon, Users, Lock, Radio } from "lucide-react";

export type AppView = "scanner" | "community" | "admin";

interface HeaderProps {
  caseId: string;
  theme: "light" | "dark";
  onToggleTheme: () => void;
  isScanning: boolean;
  view?: AppView;
  onChangeView?: (view: AppView) => void;
}

export const Header: React.FC<HeaderProps> = ({
  caseId,
  theme,
  onToggleTheme,
  isScanning,
  view = "scanner",
  onChangeView,
}) => {
  return (
    <header className="case-header">
      {/* Top utility row */}
      <div className="case-meta-bar">
        <div className="case-meta-group">
          <span className="case-id-tag">
            CASE <strong style={{ color: "var(--text)" }}>{caseId}</strong>
          </span>
          <span className="meta-sep">•</span>
          <span className="meta-format-desc">0–100 HEURISTIC ENGINE</span>
        </div>

        <div className="case-meta-group">
          <div className="status-badge" title={isScanning ? "Actively analyzing heuristics & threat intel" : "Ready for inspection"}>
            <Radio size={12} className={isScanning ? "pulse-anim text-accent" : "text-safe"} />
            <span>{isScanning ? "ANALYZING" : "STANDBY"}</span>
          </div>

          <button
            type="button"
            className="theme-toggle-btn"
            onClick={onToggleTheme}
            aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
            title={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
          >
            {theme === "light" ? <Moon size={13} /> : <Sun size={13} />}
            <span className="theme-label">{theme.toUpperCase()}</span>
          </button>
        </div>
      </div>

      {/* Main branding & navigation row */}
      <div className="app-title-row">
        <div className="brand-lockup">
          <h1 className="app-title">
            <span className="app-title-icon-wrap">
              <ShieldAlert className="app-title-flag" size={24} />
            </span>
            <span>REDFLAG INSPECTOR</span>
          </h1>
          <p className="app-subtitle">
            Forensic phishing & scam detector for job offers, recruiter emails, and rental listings.
          </p>
        </div>

        {onChangeView && (
          <nav className="view-tabs" role="tablist" aria-label="Application navigation">
            <button
              type="button"
              role="tab"
              aria-selected={view === "scanner"}
              className={`view-tab ${view === "scanner" ? "active" : ""}`}
              onClick={() => onChangeView("scanner")}
            >
              <ShieldAlert size={14} />
              <span>Scanner</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={view === "community"}
              className={`view-tab ${view === "community" ? "active" : ""}`}
              onClick={() => onChangeView("community")}
            >
              <Users size={14} />
              <span>Community</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={view === "admin"}
              className={`view-tab ${view === "admin" ? "active" : ""}`}
              onClick={() => onChangeView("admin")}
            >
              <Lock size={14} />
              <span>Admin</span>
            </button>
          </nav>
        )}
      </div>
    </header>
  );
};
