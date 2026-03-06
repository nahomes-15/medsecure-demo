import React, { useState, useMemo } from "react";
import pipelineData from "./pipeline-results.json";

const SEVERITY_COLORS = {
  error: { bg: "#2d1215", text: "#f87171", badge: "#991b1b", border: "#7f1d1d" },
  warning: { bg: "#2d2305", text: "#fbbf24", badge: "#92400e", border: "#78350f" },
  note: { bg: "#0c1929", text: "#60a5fa", badge: "#1e3a5f", border: "#1e3a5f" },
};

const STATUS_CONFIG = {
  completed: { label: "Remediated", color: "#34d399", icon: "\u2713" },
  needs_human_review: { label: "Needs Review", color: "#fbbf24", icon: "!" },
  in_progress: { label: "In Progress", color: "#60a5fa", icon: "\u2026" },
  failed: { label: "Failed", color: "#f87171", icon: "\u2717" },
  dispatched: { label: "Dispatched", color: "#a78bfa", icon: "\u2192" },
};

function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: "#111118",
      border: "1px solid #1e1e2e",
      borderRadius: 8,
      padding: "20px 24px",
      minWidth: 140,
      flex: 1,
    }}>
      <div style={{ fontSize: 32, fontWeight: 700, color, fontFamily: "monospace" }}>
        {value}
      </div>
      <div style={{ fontSize: 13, color: "#6b7280", marginTop: 4 }}>{label}</div>
    </div>
  );
}

function SeverityBadge({ level }) {
  const colors = SEVERITY_COLORS[level] || SEVERITY_COLORS.note;
  return (
    <span style={{
      background: colors.badge,
      color: colors.text,
      padding: "2px 10px",
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 600,
      textTransform: "uppercase",
      letterSpacing: "0.05em",
    }}>
      {level}
    </span>
  );
}

function StatusIndicator({ status }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.dispatched;
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 6,
      color: config.color,
      fontSize: 13,
      fontWeight: 500,
    }}>
      <span style={{
        width: 8,
        height: 8,
        borderRadius: "50%",
        background: config.color,
        display: "inline-block",
      }} />
      {config.label}
    </span>
  );
}

function ComplianceBar({ stats }) {
  const total = stats.total_sessions;
  if (total === 0) return null;
  const segments = [
    { count: stats.completed, color: "#34d399", label: "Remediated" },
    { count: stats.in_progress, color: "#60a5fa", label: "In Progress" },
    { count: stats.needs_human_review, color: "#fbbf24", label: "Needs Review" },
    { count: stats.failed, color: "#f87171", label: "Failed" },
  ];
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{
        display: "flex",
        height: 10,
        borderRadius: 5,
        overflow: "hidden",
        background: "#1e1e2e",
      }}>
        {segments.map((s, i) => s.count > 0 && (
          <div key={i} style={{
            width: `${(s.count / total) * 100}%`,
            background: s.color,
            transition: "width 0.3s",
          }} />
        ))}
      </div>
      <div style={{ display: "flex", gap: 16, marginTop: 8, flexWrap: "wrap" }}>
        {segments.map((s, i) => s.count > 0 && (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#9ca3af" }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: s.color, display: "inline-block" }} />
            {s.label}: {s.count}
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingsTable({ findings, filter }) {
  const filtered = useMemo(() => {
    if (filter === "all") return findings;
    return findings.filter((f) => f.status === filter);
  }, [findings, filter]);

  // Deduplicate for display — group by session_id, show one row per group
  const rows = useMemo(() => {
    const seen = new Map();
    for (const f of filtered) {
      const key = `${f.session_id}-${f.rule_id}-${f.file}`;
      if (!seen.has(key)) {
        seen.set(key, { ...f, lines: [f.start_line], count: 1 });
      } else {
        const existing = seen.get(key);
        if (!existing.lines.includes(f.start_line)) {
          existing.lines.push(f.start_line);
        }
        existing.count++;
      }
    }
    return Array.from(seen.values());
  }, [filtered]);

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #1e1e2e", color: "#6b7280", textAlign: "left" }}>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>Severity</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>Rule / Vulnerability</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>CWE</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>Location</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>Status</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>Links</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f, i) => {
            const colors = SEVERITY_COLORS[f.level] || SEVERITY_COLORS.note;
            return (
              <tr key={i} style={{
                borderBottom: "1px solid #111118",
                background: i % 2 === 0 ? "transparent" : "#0a0a10",
              }}>
                <td style={{ padding: "12px 16px" }}>
                  <SeverityBadge level={f.level} />
                </td>
                <td style={{ padding: "12px 16px" }}>
                  <div style={{ color: "#e5e7eb", fontWeight: 500 }}>{f.short_description}</div>
                  <div style={{ color: "#6b7280", fontSize: 11, fontFamily: "monospace", marginTop: 2 }}>
                    {f.rule_id}
                  </div>
                </td>
                <td style={{ padding: "12px 16px", fontFamily: "monospace", color: "#9ca3af", fontSize: 12 }}>
                  {f.cwe_ids.slice(0, 2).join(", ")}
                </td>
                <td style={{ padding: "12px 16px" }}>
                  <div style={{ fontFamily: "monospace", color: "#d1d5db", fontSize: 12 }}>
                    {f.file.replace("vulnerable-app/", "")}
                  </div>
                  <div style={{ fontFamily: "monospace", color: "#6b7280", fontSize: 11 }}>
                    {f.lines.length > 1
                      ? `Lines ${f.lines.join(", ")}`
                      : `Line ${f.lines[0]}`}
                    {f.count > f.lines.length && ` (${f.count} instances)`}
                  </div>
                </td>
                <td style={{ padding: "12px 16px" }}>
                  <StatusIndicator status={f.status} />
                </td>
                <td style={{ padding: "12px 16px" }}>
                  <div style={{ display: "flex", gap: 8 }}>
                    {f.pr_url && (
                      <a href={f.pr_url} target="_blank" rel="noopener noreferrer" style={{
                        color: "#34d399",
                        textDecoration: "none",
                        fontSize: 12,
                        padding: "2px 8px",
                        border: "1px solid #065f46",
                        borderRadius: 4,
                      }}>
                        PR
                      </a>
                    )}
                    {f.session_url && (
                      <a href={f.session_url} target="_blank" rel="noopener noreferrer" style={{
                        color: "#60a5fa",
                        textDecoration: "none",
                        fontSize: 12,
                        padding: "2px 8px",
                        border: "1px solid #1e3a5f",
                        borderRadius: 4,
                      }}>
                        Session
                      </a>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function SeverityBreakdown({ findings }) {
  const counts = useMemo(() => {
    const c = { error: 0, warning: 0, note: 0 };
    const seen = new Set();
    for (const f of findings) {
      const key = `${f.rule_id}-${f.file}`;
      if (!seen.has(key)) {
        seen.add(key);
        c[f.level] = (c[f.level] || 0) + 1;
      }
    }
    return c;
  }, [findings]);

  return (
    <div style={{ display: "flex", gap: 12 }}>
      {Object.entries(counts).map(([level, count]) => count > 0 && (
        <div key={level} style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 12px",
          background: SEVERITY_COLORS[level]?.bg || "#111118",
          border: `1px solid ${SEVERITY_COLORS[level]?.border || "#1e1e2e"}`,
          borderRadius: 6,
        }}>
          <span style={{
            color: SEVERITY_COLORS[level]?.text || "#9ca3af",
            fontWeight: 700,
            fontSize: 18,
            fontFamily: "monospace",
          }}>
            {count}
          </span>
          <span style={{ color: "#9ca3af", fontSize: 12, textTransform: "uppercase" }}>
            {level}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function SecurityDashboard() {
  const [filter, setFilter] = useState("all");
  const { pipeline_run: stats, findings } = pipelineData;

  const filterOptions = [
    { key: "all", label: "All" },
    { key: "completed", label: "Remediated" },
    { key: "needs_human_review", label: "Needs Review" },
    { key: "in_progress", label: "In Progress" },
    { key: "failed", label: "Failed" },
  ];

  const ts = new Date(stats.timestamp).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });

  return (
    <div style={{
      minHeight: "100vh",
      background: "#06060b",
      color: "#e5e7eb",
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    }}>
      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "32px 24px" }}>
        {/* Header */}
        <div style={{ marginBottom: 32 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
            <div style={{
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: "#34d399",
              boxShadow: "0 0 8px #34d399",
            }} />
            <h1 style={{ fontSize: 22, fontWeight: 600, margin: 0, color: "#f9fafb" }}>
              MedSecure Security Remediation Pipeline
            </h1>
          </div>
          <div style={{ color: "#6b7280", fontSize: 13, marginLeft: 22 }}>
            Last scan: {ts}
          </div>
        </div>

        {/* Stat cards */}
        <div style={{ display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
          <StatCard label="Total Findings" value={stats.total_findings} color="#e5e7eb" />
          <StatCard label="Remediated" value={stats.completed} color="#34d399" />
          <StatCard label="Needs Review" value={stats.needs_human_review} color="#fbbf24" />
          <StatCard label="In Progress" value={stats.in_progress} color="#60a5fa" />
          <StatCard label="Remediation Rate" value={`${stats.remediation_rate}%`} color="#34d399" />
        </div>

        {/* Compliance panel */}
        <div style={{
          background: "#111118",
          border: "1px solid #1e1e2e",
          borderRadius: 8,
          padding: 24,
          marginBottom: 24,
        }}>
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 16,
            flexWrap: "wrap",
            gap: 12,
          }}>
            <div>
              <h2 style={{ fontSize: 15, fontWeight: 600, margin: 0, color: "#f9fafb" }}>
                Compliance Summary
              </h2>
              <div style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}>
                {stats.total_sessions} Devin sessions across {stats.total_findings} findings
              </div>
            </div>
            <SeverityBreakdown findings={findings} />
          </div>
          <ComplianceBar stats={stats} />
        </div>

        {/* Filter tabs + Findings table */}
        <div style={{
          background: "#111118",
          border: "1px solid #1e1e2e",
          borderRadius: 8,
          overflow: "hidden",
        }}>
          <div style={{
            display: "flex",
            gap: 0,
            borderBottom: "1px solid #1e1e2e",
            padding: "0 16px",
          }}>
            {filterOptions.map((opt) => (
              <button
                key={opt.key}
                onClick={() => setFilter(opt.key)}
                style={{
                  background: "none",
                  border: "none",
                  borderBottom: filter === opt.key ? "2px solid #34d399" : "2px solid transparent",
                  color: filter === opt.key ? "#f9fafb" : "#6b7280",
                  padding: "12px 16px",
                  fontSize: 13,
                  fontWeight: 500,
                  cursor: "pointer",
                  transition: "all 0.15s",
                }}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <FindingsTable findings={findings} filter={filter} />
        </div>

        {/* Footer */}
        <div style={{
          textAlign: "center",
          padding: "24px 0 8px",
          color: "#374151",
          fontSize: 12,
        }}>
          Powered by Devin AI &middot; CodeQL Static Analysis
        </div>
      </div>
    </div>
  );
}
