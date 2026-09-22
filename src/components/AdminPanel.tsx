import React, { useEffect, useState } from "react";
import { Lock, ShieldCheck, Trash2, RotateCcw } from "lucide-react";
import { ScamReport } from "../lib/types";
import { fetchAdminReports, moderateReportAction } from "../lib/reports";

// Admin auth here is ONE shared secret (ADMIN_KEY, checked server-side in
// api/reports.ts), not a user-account system — a deliberate scope choice
// for this pass, appropriate for "the operator moderates their own
// deployment," not for multiple named admins with different permissions or
// an audit trail of who did what. A real multi-admin version would need
// actual accounts, hashed passwords or SSO, sessions, and per-action
// audit logging — meaningfully more than this hackathon-scale feature set.
//
// The key is kept in sessionStorage (cleared when the tab closes), never
// localStorage — a small deliberate choice to make it not silently persist
// across browser sessions on a shared machine.
const SESSION_KEY = "rfi_admin_key";

export const AdminPanel: React.FC = () => {
  const [keyInput, setKeyInput] = useState("");
  const [adminKey, setAdminKey] = useState<string | null>(() => {
    try {
      return sessionStorage.getItem(SESSION_KEY);
    } catch {
      return null;
    }
  });
  const [reports, setReports] = useState<ScamReport[]>([]);
  const [loading, setLoading] = useState(false);
  const [authError, setAuthError] = useState(false);

  const load = async (key: string) => {
    setLoading(true);
    setAuthError(false);
    const { reports: fetched, error } = await fetchAdminReports(key);
    setLoading(false);
    if (error === "unauthorized") {
      setAuthError(true);
      setAdminKey(null);
      try {
        sessionStorage.removeItem(SESSION_KEY);
      } catch {}
      return;
    }
    setReports(fetched || []);
  };

  useEffect(() => {
    if (adminKey) load(adminKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleLogin = () => {
    if (!keyInput.trim()) return;
    try {
      sessionStorage.setItem(SESSION_KEY, keyInput.trim());
    } catch {}
    setAdminKey(keyInput.trim());
    load(keyInput.trim());
  };

  const handleLogout = () => {
    setAdminKey(null);
    setReports([]);
    try {
      sessionStorage.removeItem(SESSION_KEY);
    } catch {}
  };

  const handleAction = async (id: string, action: "verify" | "remove" | "unverify") => {
    if (!adminKey) return;
    const { report } = await moderateReportAction(id, action, adminKey);
    if (report) {
      setReports((prev) => prev.map((r) => (r.id === id ? report : r)));
    }
  };

  if (!adminKey) {
    return (
      <section className="case-card">
        <div className="section-label">
          <Lock size={13} className="icon-inline" />
          Admin Moderation
        </div>
        <p className="section-note" style={{ marginBottom: "12px" }}>
          Enter the operator admin key (set as <code className="inline-code">ADMIN_KEY</code> in this server's{" "}
          <code className="inline-code">.env</code>) to review and moderate community reports. If{" "}
          <code className="inline-code">ADMIN_KEY</code> isn't set on the server, moderation is disabled entirely
          rather than left open.
        </p>
        {authError && (
          <p className="inline-alert danger" style={{ marginBottom: "10px" }}>
            Incorrect key, or ADMIN_KEY isn't configured on this server.
          </p>
        )}
        <div className="admin-key-box">
          <input
            type="password"
            className="form-select"
            placeholder="Admin key"
            value={keyInput}
            onChange={(e) => setKeyInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleLogin()}
            aria-label="Admin key"
          />
          <button type="button" className="report-submit-btn" onClick={handleLogin}>
            Unlock
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="case-card">
      <div className="section-header-row">
        <div className="section-label" style={{ marginBottom: 0, flex: "1 1 auto" }}>
          <Lock size={13} className="icon-inline" />
          Admin Moderation ({reports.length} reports)
        </div>
        <button type="button" className="copy-report-btn" onClick={handleLogout}>
          Lock
        </button>
      </div>

      {loading ? (
        <div className="loading-row">
          <div className="spinner" />
          <span>Loading…</span>
        </div>
      ) : reports.length === 0 ? (
        <p className="empty-state">No reports submitted yet.</p>
      ) : (
        reports.map((r) => (
          <div key={r.id} className="admin-report-row">
            <div>
              <div className="report-card-top" style={{ marginBottom: "4px" }}>
                <span className={`report-badge ${r.status}`}>{r.status}</span>
                <span className="report-meta">
                  {r.category} · {r.score}/100 {r.bandLabel} · {r.confirmCount} confirms
                </span>
              </div>
              <div className="report-preview">"{r.textPreview}"</div>
              {r.note && <div className="report-note">Note: {r.note}</div>}
              {r.domain && <div className="report-meta">Domain/contact: {r.domain}</div>}
            </div>
            <div className="action-col">
              {r.status !== "verified" && (
                <button type="button" className="admin-action-btn verify" onClick={() => handleAction(r.id, "verify")}>
                  <ShieldCheck size={11} className="icon-inline" />
                  Verify
                </button>
              )}
              {r.status === "verified" && (
                <button type="button" className="admin-action-btn" onClick={() => handleAction(r.id, "unverify")}>
                  <RotateCcw size={11} className="icon-inline" />
                  Unverify
                </button>
              )}
              {r.status !== "removed" && (
                <button type="button" className="admin-action-btn remove" onClick={() => handleAction(r.id, "remove")}>
                  <Trash2 size={11} className="icon-inline" />
                  Remove
                </button>
              )}
              {r.status === "removed" && (
                <button type="button" className="admin-action-btn" onClick={() => handleAction(r.id, "unverify")}>
                  <RotateCcw size={11} className="icon-inline" />
                  Restore
                </button>
              )}
            </div>
          </div>
        ))
      )}
    </section>
  );
};
