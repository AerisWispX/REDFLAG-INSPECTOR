import React, { useState, useEffect, useCallback, useRef } from "react";
import { Header, AppView } from "./components/Header";
import { InputConsole, SAMPLES } from "./components/InputConsole";
import { DoNotCallout } from "./components/DoNotCallout";
import { ThreatGauge } from "./components/ThreatGauge";
import { ScoreBreakdown } from "./components/ScoreBreakdown";
import { CategoryBreakdown } from "./components/CategoryBreakdown";
import { Recommendations } from "./components/Recommendations";
import { LiveVerificationPanel } from "./components/LiveVerificationPanel";
import { AiAnalysisPanel } from "./components/AiAnalysisPanel";
import { ScanHistoryPanel } from "./components/ScanHistoryPanel";
import { ReportButton } from "./components/ReportButton";
import { ReportsFeed } from "./components/ReportsFeed";
import { AdminPanel } from "./components/AdminPanel";
import { scanText, band, applyLiveEnrichment } from "./lib/scoring";
import { extractEmails, extractUrls } from "./lib/extract";
import {
  generateCaseId,
  loadHistory,
  saveScanToHistory,
  clearAllData,
} from "./lib/history";
import { decodeShareFromHash, SharedReport } from "./lib/share";
import {
  AiAnalysis,
  EmailEnrichment,
  EnrichResponse,
  ScanHistoryEntry,
  ScanResult,
  UrlEnrichment,
} from "./lib/types";

export const App: React.FC = () => {
  // Theme state: light or dark
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    if (typeof window !== "undefined" && window.matchMedia) {
      return window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    }
    return "light";
  });

  // Top-level view tab
  const [view, setView] = useState<AppView>("scanner");

  // State
  const [caseId, setCaseId] = useState<string>(() => generateCaseId());
  const [inputText, setInputText] = useState<string>(SAMPLES.scam);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isEnriching, setIsEnriching] = useState<boolean>(false);

  // Scan analysis results
  const [scanResult, setScanResult] = useState<ScanResult>(() => scanText(SAMPLES.scam));
  const [forceSevere, setForceSevere] = useState<boolean>(false);

  // Enrichment state
  const [extractedEmails, setExtractedEmails] = useState<string[]>([]);
  const [extractedUrls, setExtractedUrls] = useState<string[]>([]);
  const [emailEnrichments, setEmailEnrichments] = useState<EmailEnrichment[]>([]);
  const [urlEnrichments, setUrlEnrichments] = useState<UrlEnrichment[]>([]);
  const [aiAnalysis, setAiAnalysis] = useState<AiAnalysis | undefined>(undefined);
  const [hasScanned, setHasScanned] = useState<boolean>(false);

  // Local storage history
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);

  // Shared-report read-only mode
  const [sharedReport, setSharedReport] = useState<SharedReport | null>(null);

  // Toggle theme
  const toggleTheme = () => {
    setTheme((prev) => {
      const next = prev === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      return next;
    });
  };

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  // Main scan runner
  const executeScan = useCallback(
    async (textToScan: string) => {
      if (!textToScan.trim()) {
        const emptyResult = scanText("");
        setScanResult(emptyResult);
        setForceSevere(false);
        setExtractedEmails([]);
        setExtractedUrls([]);
        setEmailEnrichments([]);
        setUrlEnrichments([]);
        setAiAnalysis(undefined);
        return;
      }

      setIsScanning(true);
      const newCaseId = generateCaseId();
      setCaseId(newCaseId);

      // 1. Instant local heuristic scan
      const localResult = scanText(textToScan);
      setScanResult(localResult);
      setForceSevere(false);

      const emails = extractEmails(textToScan);
      const urls = extractUrls(textToScan);
      setExtractedEmails(emails);
      setExtractedUrls(urls);
      setEmailEnrichments([]);
      setUrlEnrichments([]);
      setAiAnalysis(undefined);

      const initialBand = band(localResult.score);

      // Persist to local history immediately with initial heuristic findings
      const updatedHistory = saveScanToHistory({
        caseId: newCaseId,
        score: localResult.score,
        bandKey: initialBand.key,
        bandLabel: initialBand.label,
        text: textToScan,
      });
      setHistory(updatedHistory);
      setIsScanning(false);

      // 2. Progressive enrichment: always query the backend for threat intel & Groq AI
      setIsEnriching(true);
      try {
        const resp = await fetch("/api/enrich", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: textToScan }),
        });

        if (resp.ok) {
          const data: EnrichResponse = await resp.json();
          setEmailEnrichments(data.emails || []);
          setUrlEnrichments(data.urls || []);
          setAiAnalysis(data.aiAnalysis);

          // Recompute score with live threat intel (+ bounded AI nudge) if hits found
          const enriched = applyLiveEnrichment(localResult, data);
          setScanResult(enriched.result);
          setForceSevere(enriched.forceSevere);

          const enrichedBand = band(enriched.result.score, enriched.forceSevere);
          const refreshedHistory = saveScanToHistory({
            caseId: newCaseId,
            score: enriched.result.score,
            bandKey: enrichedBand.key,
            bandLabel: enrichedBand.label,
            text: textToScan,
          });
          setHistory(refreshedHistory);
        }
      } catch {
        // Graceful fallback: local heuristics already completed
      } finally {
        setIsEnriching(false);
        setHasScanned(true);
      }
    },
    []
  );

  // Initial mount behavior
  const initialMountRef = useRef(false);
  useEffect(() => {
    if (!initialMountRef.current) {
      initialMountRef.current = true;
      setHistory(loadHistory());

      const shared = decodeShareFromHash(window.location.hash);
      if (shared) {
        setSharedReport(shared);
        return;
      }
      executeScan(SAMPLES.scam);
    }
  }, [executeScan]);

  const handleClearHistory = () => {
    clearAllData();
    setHistory([]);
  };

  const handleSelectHistoryEntry = (entry: ScanHistoryEntry) => {
    const textToLoad = entry.fullText || entry.preview;
    setInputText(textToLoad);
    executeScan(textToLoad);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleExitSharedView = () => {
    setSharedReport(null);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    executeScan(SAMPLES.scam);
  };

  const currentBand = band(scanResult.score, forceSevere);
  const hasFloorActive =
    scanResult.score >= 55 &&
    scanResult.categories.some(
      (c) => c.hits.reduce((acc, h) => acc + h.points, 0) >= 70
    );

  // Shared-report read-only view
  if (sharedReport) {
    const sharedBand = band(sharedReport.scanResult.score);
    return (
      <div className="app-container">
        <Header caseId={sharedReport.caseId} theme={theme} onToggleTheme={toggleTheme} isScanning={false} />
        <main className="shared-report-main">
          <section className="case-card" style={{ borderColor: "var(--accent)" }}>
            <div className="section-label">Shared Forensic Dossier (Read-Only)</div>
            <p style={{ fontSize: "13px", color: "var(--text-dim)", margin: "6px 0 12px" }}>
              Viewing a scan shared via link — decoded completely in your browser from the URL fragment. Nothing was fetched from or stored on any server.
              Scanned on {new Date(sharedReport.timestamp).toLocaleString()}.
            </p>
            <button type="button" className="scan-submit-btn" onClick={handleExitSharedView}>
              <span>Scan your own material →</span>
            </button>
          </section>

          <DoNotCallout items={sharedReport.scanResult.doNotItems} bandKey={sharedBand.key} />

          <section className="case-card">
            <div className="section-label">02 — Scam Threat Index & Verdict</div>
            <ThreatGauge score={sharedReport.scanResult.score} bandInfo={sharedBand} confidence={sharedReport.scanResult.confidence} />
            <ScoreBreakdown
              score={sharedReport.scanResult.score}
              breakdown={sharedReport.scanResult.breakdown}
              isFloorActive={
                sharedReport.scanResult.score >= 55 &&
                sharedReport.scanResult.categories.some((c) => c.hits.reduce((acc, h) => acc + h.points, 0) >= 70)
              }
            />
          </section>

          <CategoryBreakdown categories={sharedReport.scanResult.categories} />

          <Recommendations
            categories={sharedReport.scanResult.categories}
            caseId={sharedReport.caseId}
            scannedText={sharedReport.scannedTextPreview}
            scanResult={sharedReport.scanResult}
          />
        </main>
      </div>
    );
  }

  return (
    <div className="app-container">
      <Header
        caseId={caseId}
        theme={theme}
        onToggleTheme={toggleTheme}
        isScanning={isScanning || isEnriching}
        view={view}
        onChangeView={setView}
      />

      {view === "community" ? (
        <main className="view-container">
          <ReportsFeed />
        </main>
      ) : view === "admin" ? (
        <main className="view-container">
          <AdminPanel />
        </main>
      ) : (
        <main className="inspector-grid">
          {/* Left / Primary Inspector Column */}
          <div className="inspector-primary">
            {/* 01: Submit material */}
            <div className="grid-item-input">
              <InputConsole
                text={inputText}
                onChangeText={setInputText}
                onScan={() => executeScan(inputText)}
                isScanning={isScanning || isEnriching}
              />
            </div>

            {/* Immediate-actions callout (High/Severe only) */}
            <div className="grid-item-donot">
              <DoNotCallout
                items={scanResult.doNotItems}
                bandKey={currentBand.key}
              />
            </div>

            {/* 03: Signal & Heuristic Breakdown */}
            <div className="grid-item-categories">
              <CategoryBreakdown categories={scanResult.categories} />
            </div>

            {/* 04: Recommended Actions & Report Copy / Share */}
            <div className="grid-item-recommendations">
              <Recommendations
                categories={scanResult.categories}
                caseId={caseId}
                scannedText={inputText}
                scanResult={scanResult}
              />
            </div>

            {/* 05: Live Threat-Intel Panel */}
            <div className="grid-item-live">
              <LiveVerificationPanel
                isLoading={isEnriching}
                emails={extractedEmails}
                urls={extractedUrls}
                emailResults={emailEnrichments}
                urlResults={urlEnrichments}
              />
            </div>

            {/* 06: Local Scan History */}
            <div className="grid-item-history">
              <ScanHistoryPanel
                history={history}
                onClearHistory={handleClearHistory}
                onSelectEntry={handleSelectHistoryEntry}
              />
            </div>
          </div>

          {/* Right / Sidebar Column */}
          <div className="inspector-sidebar">
            {/* 02: Threat Index & Verdict */}
            <div className="grid-item-gauge">
              <section className="case-card gauge-summary-card">
                <div className="section-label">02 — Scam Threat Index</div>
                <ThreatGauge
                  score={scanResult.score}
                  bandInfo={currentBand}
                  confidence={scanResult.confidence}
                />
                <ScoreBreakdown
                  score={scanResult.score}
                  breakdown={scanResult.breakdown}
                  isFloorActive={hasFloorActive}
                />
              </section>
            </div>

            {/* 07: AI Analysis (Groq) */}
            <div className="grid-item-ai">
              <AiAnalysisPanel isLoading={isEnriching} analysis={aiAnalysis} hasScanned={hasScanned} />
            </div>

            {/* Help others avoid this (Community Reporting) */}
            <div className="grid-item-community">
              <section className="case-card">
                <div className="section-label">Community Alert</div>
                <ReportButton
                  scannedText={inputText}
                  scanResult={scanResult}
                  forceSevere={forceSevere}
                  extractedEmails={extractedEmails}
                  extractedUrls={extractedUrls}
                />
              </section>
            </div>
          </div>
        </main>
      )}
    </div>
  );
};

export default App;
