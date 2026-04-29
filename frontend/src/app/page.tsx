"use client";

import { useState } from "react";

type Severity = "Critical" | "High" | "Medium" | "Low";

interface AnalysisResult {
  threatType: string;
  severity: Severity;
  explanation: string;
  actions: string[];
}

const SEVERITY_BADGE: Record<Severity, string> = {
  Critical: "badge badge-critical",
  High: "badge badge-high",
  Medium: "badge badge-medium",
  Low: "badge badge-low",
};

// Lightweight mock analysis — replace with real API call
function analyzeLog(log: string): AnalysisResult {
  const l = log.toLowerCase();

  if (l.includes("sql") || l.includes("union select") || l.includes("drop table")) {
    return {
      threatType: "SQL Injection Attack",
      severity: "Critical",
      explanation:
        "Malicious SQL statements detected in the input stream. An attacker is attempting to manipulate backend database queries, potentially exfiltrating sensitive data or destroying records.",
      actions: [
        "Immediately block the source IP at the WAF/firewall level.",
        "Sanitize and parameterize all database queries using prepared statements.",
        "Audit database access logs for unauthorized reads or modifications.",
        "Rotate database credentials and review user privilege assignments.",
        "Enable query-level anomaly detection on your SIEM.",
      ],
    };
  }

  if (l.includes("brute force") || l.includes("failed login") || l.includes("invalid password") || l.includes("authentication failure")) {
    return {
      threatType: "Brute Force / Credential Stuffing",
      severity: "High",
      explanation:
        "Multiple consecutive authentication failures detected from a single source. This pattern is consistent with automated credential stuffing or dictionary-based brute force attacks targeting user accounts.",
      actions: [
        "Temporarily lock the targeted account and notify the account owner.",
        "Rate-limit or CAPTCHA-gate the login endpoint.",
        "Block the offending IP range via firewall rules.",
        "Enable multi-factor authentication (MFA) for all privileged accounts.",
        "Cross-reference credentials against known breach databases (HaveIBeenPwned).",
      ],
    };
  }

  if (l.includes("xss") || l.includes("<script") || l.includes("javascript:") || l.includes("onerror=")) {
    return {
      threatType: "Cross-Site Scripting (XSS)",
      severity: "High",
      explanation:
        "Unsanitized script injection payload detected in HTTP request parameters. If rendered by the browser, this could allow session hijacking, credential theft, or malicious redirects.",
      actions: [
        "Encode all user-supplied output using context-aware escaping.",
        "Implement a strict Content Security Policy (CSP) header.",
        "Validate and whitelist allowed HTML tags via a sanitization library.",
        "Audit all input fields and URL parameters for reflected/stored XSS vectors.",
        "Review session cookie flags (HttpOnly, Secure, SameSite).",
      ],
    };
  }

  if (l.includes("port scan") || l.includes("nmap") || l.includes("syn flood") || l.includes("ddos") || l.includes("dos")) {
    return {
      threatType: "Network Reconnaissance / DoS",
      severity: "Medium",
      explanation:
        "Unusual network traffic patterns suggest active port scanning or a denial-of-service attempt. The attacker may be mapping your infrastructure prior to a targeted intrusion.",
      actions: [
        "Block the scanning IP at the network perimeter.",
        "Enable rate-limiting and SYN cookie protection on exposed services.",
        "Review firewall rules to ensure only required ports are exposed.",
        "Alert the network operations team for traffic analysis.",
        "Consider activating DDoS mitigation (e.g., AWS Shield, Cloudflare).",
      ],
    };
  }

  if (l.includes("malware") || l.includes("ransomware") || l.includes("trojan") || l.includes("virus") || l.includes("payload")) {
    return {
      threatType: "Malware / Ransomware Indicator",
      severity: "Critical",
      explanation:
        "Signatures consistent with known malware or ransomware behavior detected. Immediate containment is required to prevent lateral movement and data encryption across the network.",
      actions: [
        "Isolate the affected host from the network immediately.",
        "Preserve forensic evidence — do not power off the machine.",
        "Run a full endpoint detection and response (EDR) scan.",
        "Identify and revoke any compromised credentials or tokens.",
        "Initiate incident response playbook and notify stakeholders.",
      ],
    };
  }

  return {
    threatType: "Anomalous Activity Detected",
    severity: "Low",
    explanation:
      "The log entry contains patterns that deviate from baseline behavior but do not match a known high-severity attack signature. Further investigation is recommended to rule out false positives.",
    actions: [
      "Correlate this event with other logs in the same time window.",
      "Check if the source IP appears in threat intelligence feeds.",
      "Review user activity history for the associated account.",
      "Escalate to Tier 2 analyst if pattern persists.",
    ],
  };
}

export default function Home() {
  const [log, setLog] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [scanning, setScanning] = useState(false);

  async function handleAnalyze() {
    if (!log.trim()) return;
    setScanning(true);
    setResult(null);
    // Simulate async API latency
    await new Promise((r) => setTimeout(r, 1400));
    setResult(analyzeLog(log));
    setScanning(false);
  }

  return (
    <main
      style={{
        position: "relative",
        zIndex: 1,
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "32px 16px",
      }}
    >
      {/* Header */}
      <div style={{ textAlign: "center", marginBottom: "36px" }}>
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "10px",
            marginBottom: "12px",
          }}
        >
          {/* Shield icon */}
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none">
            <path
              d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6L12 2z"
              fill="none"
              stroke="url(#shieldGrad)"
              strokeWidth="1.5"
              strokeLinejoin="round"
            />
            <path
              d="M9 12l2 2 4-4"
              stroke="#00ff88"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <defs>
              <linearGradient id="shieldGrad" x1="3" y1="2" x2="21" y2="23">
                <stop offset="0%" stopColor="#00e5ff" />
                <stop offset="100%" stopColor="#00ff88" />
              </linearGradient>
            </defs>
          </svg>
          <h1 className="neon-title" style={{ fontSize: "clamp(2rem, 5vw, 3rem)", fontWeight: 800, margin: 0, letterSpacing: "-0.02em" }}>
            SentinelAI
          </h1>
        </div>
        <p style={{ color: "#4a7a9b", fontSize: "0.95rem", letterSpacing: "0.12em", textTransform: "uppercase", margin: 0 }}>
          AI-Powered SOC Analyst Assistant
        </p>
      </div>

      {/* Main card */}
      <div className="cyber-card" style={{ width: "100%", maxWidth: "720px", padding: "clamp(20px, 4vw, 36px)" }}>

        {/* Status bar */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
          <div className="status-bar">
            <span className="status-dot" />
            <span>System Online</span>
          </div>
          <span style={{ fontSize: "0.7rem", color: "#1a4a6b", letterSpacing: "0.1em", fontFamily: "var(--font-geist-mono)" }}>
            v2.4.1 · SENTINEL
          </span>
        </div>

        <hr className="cyber-divider" style={{ marginBottom: "24px" }} />

        {/* Input */}
        <div style={{ marginBottom: "16px" }}>
          <label className="section-label" style={{ display: "block", marginBottom: "10px" }}>
            ▸ Security Log Input
          </label>
          <textarea
            className="cyber-textarea"
            rows={7}
            placeholder="Paste your security alert or log here..."
            value={log}
            onChange={(e) => setLog(e.target.value)}
          />
        </div>

        {/* Button */}
        <button
          className={`cyber-btn${scanning ? " scanning" : ""}`}
          onClick={handleAnalyze}
          disabled={scanning || !log.trim()}
          style={{ marginBottom: result ? "28px" : "0" }}
        >
          {scanning ? (
            <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "10px" }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" style={{ animation: "spin 1s linear infinite" }}>
                <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" strokeDasharray="31.4" strokeDashoffset="10" />
              </svg>
              Scanning Threat...
            </span>
          ) : (
            "⚡ Analyze Threat"
          )}
        </button>

        {/* Output */}
        {result && (
          <div className="output-panel">
            {/* Panel header */}
            <div
              style={{
                padding: "12px 18px",
                background: "rgba(0, 229, 255, 0.04)",
                borderBottom: "1px solid #0d2a3f",
                display: "flex",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="#00e5ff">
                <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6L12 2z" />
              </svg>
              <span style={{ fontSize: "0.72rem", fontWeight: 700, letterSpacing: "0.15em", color: "#00e5ff", textTransform: "uppercase" }}>
                Threat Analysis Report
              </span>
            </div>

            <div style={{ padding: "20px 18px", display: "flex", flexDirection: "column", gap: "20px" }}>

              {/* Threat Type + Severity */}
              <div style={{ display: "flex", flexWrap: "wrap", gap: "20px" }}>
                <div style={{ flex: 1, minWidth: "180px" }}>
                  <div className="section-label" style={{ marginBottom: "6px" }}>Threat Type</div>
                  <div style={{ fontSize: "1rem", fontWeight: 600, color: "#e2f0ff" }}>{result.threatType}</div>
                </div>
                <div>
                  <div className="section-label" style={{ marginBottom: "6px" }}>Severity</div>
                  <span className={SEVERITY_BADGE[result.severity]}>{result.severity}</span>
                </div>
              </div>

              <hr className="cyber-divider" />

              {/* Explanation */}
              <div>
                <div className="section-label" style={{ marginBottom: "8px" }}>Explanation</div>
                <p style={{ margin: 0, fontSize: "0.875rem", color: "#a8c8e8", lineHeight: 1.7 }}>
                  {result.explanation}
                </p>
              </div>

              <hr className="cyber-divider" />

              {/* Actions */}
              <div>
                <div className="section-label" style={{ marginBottom: "10px" }}>Recommended Actions</div>
                <div>
                  {result.actions.map((action, i) => (
                    <div key={i} className="action-item">
                      <span className="action-bullet">▶</span>
                      <span>{action}</span>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <p style={{ marginTop: "28px", fontSize: "0.72rem", color: "#1a3a52", letterSpacing: "0.08em", textAlign: "center" }}>
        SENTINELAI · SECURITY OPERATIONS CENTER · CONFIDENTIAL
      </p>

      {/* Spin keyframe */}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </main>
  );
}
