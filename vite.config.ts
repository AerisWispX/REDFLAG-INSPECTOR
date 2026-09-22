import { defineConfig, loadEnv, Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { handleEnrich } from "./api/enrich";
import {
  handleListReports,
  handleSubmitReport,
  handleConfirmReport,
  handleModerateReport,
  handleAdminList,
} from "./api/reports";
import { apiLimiter } from "./src/lib/rateLimit";
import { getClientIp, readJsonBody } from "./api/ip";

function sendJson(res: any, status: number, body: unknown, extraHeaders?: Record<string, string>) {
  res.setHeader("Content-Type", "application/json");
  for (const [k, v] of Object.entries(extraHeaders || {})) res.setHeader(k, v);
  res.statusCode = status;
  res.end(JSON.stringify(body));
}

// Baseline security headers on every response, API and page alike — cheap,
// standard, and worth having even for a hackathon-scale server. Not a
// substitute for a real CSP (which this static-HTML-plus-Vite setup would
// need to hand-tune against Vite's own dev-time inline scripts to avoid
// breaking HMR), just the headers that cost nothing to always send.
function applySecurityHeaders(): Plugin {
  return {
    name: "security-headers-plugin",
    configureServer(server) {
      server.middlewares.use((_req, res, next) => {
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("Referrer-Policy", "same-origin");
        res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        next();
      });
    },
  };
}

function apiEnrichPlugin(): Plugin {
  return {
    name: "api-enrich-plugin",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (req.url === "/api/enrich" && req.method === "POST") {
          // Per-IP rate limit on this app's own endpoint, protecting the
          // operator's own EmailRep/WHOIS/SafeBrowsing/AbuseIPDB/VirusTotal
          // key quotas from being drained by repeated hammering.
          const ip = getClientIp(req as any);
          if (!apiLimiter.tryConsume(ip)) {
            const retryAfterSec = Math.ceil(apiLimiter.retryAfterMs(ip) / 1000);
            sendJson(res, 429, { error: "rate_limited", retryAfterSeconds: retryAfterSec }, { "Retry-After": String(retryAfterSec) });
            return;
          }

          try {
            const parsed = await readJsonBody(req as any);
            const result = await handleEnrich(parsed.text || "");
            sendJson(res, 200, result);
          } catch (err) {
            sendJson(res, 200, { emails: [], urls: [], error: "unavailable" });
          }
          return;
        }
        next();
      });
    },
  };
}

// Handles the community-reporting surface: GET/POST /api/reports,
// POST /api/reports/:id/confirm, POST /api/reports/:id/moderate, and the
// admin-only GET /api/admin/reports. See api/reports.ts for the actual
// logic — this plugin is routing + request parsing only.
function apiReportsPlugin(): Plugin {
  return {
    name: "api-reports-plugin",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const url = req.url || "";
        const ip = getClientIp(req as any);

        if (url === "/api/reports" && req.method === "GET") {
          const reports = await handleListReports();
          sendJson(res, 200, { reports });
          return;
        }

        if (url === "/api/reports" && req.method === "POST") {
          const body = await readJsonBody(req as any);
          const result = await handleSubmitReport(body, ip);
          if (result.rateLimited) return sendJson(res, 429, { error: "rate_limited" });
          if (result.error) return sendJson(res, 400, { error: result.error });
          return sendJson(res, 200, { report: result.report });
        }

        const confirmMatch = /^\/api\/reports\/([^/]+)\/confirm$/.exec(url);
        if (confirmMatch && req.method === "POST") {
          const result = await handleConfirmReport(decodeURIComponent(confirmMatch[1]), ip);
          if (result.rateLimited) return sendJson(res, 429, { error: "rate_limited" });
          if (result.error === "not_found") return sendJson(res, 404, { error: "not_found" });
          if (result.error) return sendJson(res, 400, { error: result.error });
          return sendJson(res, 200, { report: result.report });
        }

        const moderateMatch = /^\/api\/reports\/([^/]+)\/moderate$/.exec(url);
        if (moderateMatch && req.method === "POST") {
          const body = await readJsonBody(req as any);
          const adminKey = req.headers["x-admin-key"] as string | undefined;
          const result = await handleModerateReport(decodeURIComponent(moderateMatch[1]), body.action, adminKey);
          if (result.error === "unauthorized") return sendJson(res, 401, { error: "unauthorized" });
          if (result.error === "not_found") return sendJson(res, 404, { error: "not_found" });
          if (result.error) return sendJson(res, 400, { error: result.error });
          return sendJson(res, 200, { report: result.report });
        }

        if (url === "/api/admin/reports" && req.method === "GET") {
          const adminKey = req.headers["x-admin-key"] as string | undefined;
          const result = await handleAdminList(adminKey);
          if (result.error === "unauthorized") return sendJson(res, 401, { error: "unauthorized" });
          return sendJson(res, 200, { reports: result.reports });
        }

        next();
      });
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  // Vite only exposes VITE_-prefixed vars to client code by default; api/enrich.ts
  // reads plain process.env.EMAILREP_KEY etc. server-side, so we load *all*
  // .env vars (empty prefix) and copy them onto process.env ourselves — without
  // this, every key in .env is silently never seen by the dev-server middleware
  // below (this was actually the case until this fix: all five API keys were
  // present in .env but process.env.* was always undefined in dev).
  const env = loadEnv(mode, process.cwd(), "");
  Object.assign(process.env, env);

  return {
    plugins: [react(), applySecurityHeaders(), apiEnrichPlugin(), apiReportsPlugin()],
    server: {
      port: 5173,
      host: true,
    },
  };
});
