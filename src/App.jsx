import React, { useMemo, useState } from "react";

const SAMPLE_REPORT = {
  metadata: {
    source_file: "sample_logs.jsonl",
    generated_utc: "2026-11-24T12:00:00+00:00",
    lines_processed: 9,
    valid_events: 9,
    schema_errors: 0
  },
  findings: [
    {
      rule_id: "SEC-002",
      severity: "CRITICAL",
      title: "High-Risk Privilege Escalation or Sensitive File Access",
      source_ip: "185.220.101.42",
      user: "deploy",
      event_count: 1,
      first_seen: "2026-11-24T08:12:14+00:00",
      evidence: ["L7: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow"]
    },
    {
      rule_id: "SEC-004",
      severity: "CRITICAL",
      title: "Successful Authentication Following Brute-Force Activity",
      source_ip: "185.220.101.42",
      user: "deploy",
      event_count: 1,
      first_seen: "2026-11-24T08:11:02+00:00",
      evidence: ["L6: Accepted password for deploy from 185.220.101.42 port 51488 ssh2"]
    },
    {
      rule_id: "SEC-001",
      severity: "HIGH",
      title: "Authentication Brute-Force Burst Detected",
      source_ip: "185.220.101.42",
      user: "admin, deploy, root",
      event_count: 5,
      first_seen: "2026-11-24T08:10:01+00:00",
      evidence: [
        "L1: Failed password for deploy from 185.220.101.42 port 51422 ssh2",
        "L2: Failed password for deploy from 185.220.101.42 port 51425 ssh2"
      ]
    },
    {
      rule_id: "SEC-003",
      severity: "HIGH",
      title: "Sensitive Endpoint / Path Traversal Probing",
      source_ip: "45.33.32.156",
      user: "anonymous",
      event_count: 1,
      first_seen: "2026-11-24T09:04:11+00:00",
      evidence: ["L8: GET /.env HTTP/1.1 404 from 45.33.32.156"]
    }
  ]
};

function normalizeItems(rawData) {
  if (!rawData || typeof rawData !== "object") return [];
  if (Array.isArray(rawData.findings)) {
    return rawData.findings.map((f, idx) => ({
      id: `${f.rule_id || "RULE"}-${idx}`,
      rule: f.rule_id || "N/A",
      severity: (f.severity || "MEDIUM").toUpperCase(),
      title: f.title || "Finding",
      target: f.source_ip || f.user || "N/A",
      count: f.event_count ?? 1,
      timestamp: f.first_seen || "",
      evidence: Array.isArray(f.evidence) ? f.evidence : []
    }));
  }
  if (Array.isArray(rawData.issues)) {
    return rawData.issues.map((item, idx) => ({
      id: `${item.code || "ISS"}-${idx}`,
      rule: item.code || "N/A",
      severity: (item.severity || "WARN").toUpperCase(),
      title: item.message || "Audit issue",
      target: item.task_id || item.clip_id || item.item_id || "N/A",
      count: 1,
      timestamp: item.line_number ? `Line ${item.line_number}` : "",
      evidence: []
    }));
  }
  return [];
}

export default function App() {
  const [report, setReport] = useState(SAMPLE_REPORT);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [query, setQuery] = useState("");

  const items = useMemo(() => normalizeItems(report), [report]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items.filter((item) => {
      const sevMatch = severityFilter === "ALL" || item.severity === severityFilter;
      if (!sevMatch) return false;
      if (!q) return true;
      return (
        item.rule.toLowerCase().includes(q) ||
        item.title.toLowerCase().includes(q) ||
        item.target.toLowerCase().includes(q) ||
        item.evidence.some((e) => e.toLowerCase().includes(q))
      );
    });
  }, [items, severityFilter, query]);

  const counts = useMemo(() => {
    return items.reduce(
      (acc, item) => {
        acc.total += 1;
        if (item.severity === "CRITICAL" || item.severity === "ERROR") acc.critical += 1;
        else if (item.severity === "HIGH") acc.high += 1;
        else acc.other += 1;
        return acc;
      },
      { total: 0, critical: 0, high: 0, other: 0 }
    );
  }, [items]);

  function handleFileUpload(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = JSON.parse(String(e.target?.result || "{}"));
        setReport(parsed);
      } catch {
        alert("Invalid JSON report file.");
      }
    };
    reader.readAsText(file);
  }

  function exportFilteredJson() {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "filtered_triage_findings.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="app-shell">
      <header className="header">
        <div>
          <h1>Incident & Audit Triage Dashboard</h1>
          <p>Inspect JSON audit reports from CLI triage and validation tools</p>
        </div>
        <div className="actions">
          <label className="upload-btn">
            Load JSON Report
            <input type="file" accept=".json,application/json" onChange={handleFileUpload} />
          </label>
          <button type="button" onClick={() => setReport(SAMPLE_REPORT)}>
            Reset Sample
          </button>
          <button type="button" onClick={exportFilteredJson}>
            Export Filtered JSON
          </button>
        </div>
      </header>

      <section className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Findings</div>
          <div className="stat-value">{counts.total}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Critical / Error</div>
          <div className="stat-value">{counts.critical}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">High Severity</div>
          <div className="stat-value">{counts.high}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Visible Matches</div>
          <div className="stat-value">{filtered.length}</div>
        </div>
      </section>

      <section className="filters">
        <input
          type="search"
          placeholder="Filter by rule ID, IP, user, task, or evidence..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="ERROR">ERROR</option>
          <option value="WARN">WARN</option>
          <option value="MEDIUM">MEDIUM</option>
        </select>
      </section>

      <section className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule</th>
              <th>Finding / Detail</th>
              <th>Target / Source</th>
              <th>Count</th>
              <th>Time / Location</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6}>No matching findings for the active filter.</td>
              </tr>
            ) : (
              filtered.map((item) => (
                <tr key={item.id}>
                  <td>
                    <span className={`badge badge-${item.severity}`}>{item.severity}</span>
                  </td>
                  <td>
                    <code>{item.rule}</code>
                  </td>
                  <td>
                    <div>{item.title}</div>
                    {item.evidence.length > 0 && (
                      <ul className="evidence-list">
                        {item.evidence.map((ev, i) => (
                          <li key={i}>{ev}</li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td>
                    <code>{item.target}</code>
                  </td>
                  <td>{item.count}</td>
                  <td>{item.timestamp || "-"}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
