// mockData.js — simulated multi-stage attack telemetry
window.MOCK_GRAPH = (() => {
  const NODES = [
    // Endpoints
    { id: "ep-01", type: "endpoint", label: "WIN-DC01",      ip: "10.0.0.1",   risk: 92, severity: "CRITICAL", os: "Windows Server 2019" },
    { id: "ep-02", type: "endpoint", label: "FIN-WKS-07",    ip: "10.0.2.47",  risk: 78, severity: "HIGH",     os: "Windows 11 Pro" },
    { id: "ep-03", type: "endpoint", label: "DEV-MAC-12",    ip: "10.0.3.12",  risk: 14, severity: "LOW",      os: "macOS 14.4" },
    // Users
    { id: "u-01",  type: "user",     label: "j.harker",      risk: 88, severity: "HIGH",     dept: "Finance" },
    { id: "u-02",  type: "user",     label: "svc_backup",    risk: 95, severity: "CRITICAL", dept: "Service" },
    { id: "u-03",  type: "user",     label: "a.lopez",       risk: 12, severity: "LOW",      dept: "Engineering" },
    // Processes
    { id: "p-01",  type: "process",  label: "powershell.exe", risk: 90, severity: "CRITICAL", pid: 4128, cmd: "-enc JABjAD0AJwBoAHQAdABwAHMAOgA..." },
    { id: "p-02",  type: "process",  label: "rundll32.exe",   risk: 81, severity: "HIGH",     pid: 6044, cmd: "rundll32 dllhost.dll,Entry" },
    { id: "p-03",  type: "process",  label: "svchost.exe",    risk: 18, severity: "LOW",      pid: 1024, cmd: "svchost.exe -k netsvcs" },
    { id: "p-04",  type: "process",  label: "cmd.exe",        risk: 64, severity: "MEDIUM",   pid: 7700, cmd: "cmd /c whoami /priv" },
    // IPs / domains
    { id: "ip-01", type: "ip",       label: "185.220.101.42", risk: 96, severity: "CRITICAL", country: "RU",  asn: "AS9009 · TOR exit" },
    { id: "ip-02", type: "ip",       label: "c2.evilcdn.io",  risk: 94, severity: "CRITICAL", country: "—",   asn: "Newly registered · 4h" },
    { id: "ip-03", type: "ip",       label: "8.8.8.8",        risk: 5,  severity: "LOW",      country: "US",  asn: "AS15169 Google" },
    // Files
    { id: "f-01",  type: "file",     label: "invoice_q3.docm", risk: 89, severity: "HIGH",     path: "C:\\Users\\j.harker\\Downloads\\", hash: "a3f7…b0e2" },
    { id: "f-02",  type: "file",     label: "loader.dll",     risk: 97, severity: "CRITICAL", path: "C:\\ProgramData\\Microsoft\\", hash: "9d11…ca44" },
    { id: "f-03",  type: "file",     label: "ntds.dit",       risk: 98, severity: "CRITICAL", path: "C:\\Windows\\NTDS\\",      hash: "bc02…ee7f" },
  ];

  const EDGES = [
    // Attack chain (malicious path) — order = animation order
    { source: "u-01",  target: "f-01",  type: "downloaded", malicious: true, ts: "10:22:14", chain: 1 },
    { source: "f-01",  target: "p-01",  type: "executed",   malicious: true, ts: "10:22:31", chain: 2 },
    { source: "p-01",  target: "ip-02", type: "connected",  malicious: true, ts: "10:22:44", chain: 3 },
    { source: "ip-02", target: "f-02",  type: "dropped",    malicious: true, ts: "10:23:09", chain: 4 },
    { source: "p-01",  target: "p-02",  type: "spawned",    malicious: true, ts: "10:23:18", chain: 5 },
    { source: "p-02",  target: "ep-01", type: "lateral",    malicious: true, ts: "10:24:02", chain: 6 },
    { source: "ep-01", target: "u-02",  type: "auth",       malicious: true, ts: "10:24:21", chain: 7 },
    { source: "u-02",  target: "f-03",  type: "accessed",   malicious: true, ts: "10:24:55", chain: 8 },
    { source: "f-03",  target: "ip-01", type: "exfil",      malicious: true, ts: "10:25:12", chain: 9 },

    // Background normal activity
    { source: "ep-02", target: "u-01",  type: "auth",       malicious: false },
    { source: "ep-02", target: "p-04",  type: "spawned",    malicious: false },
    { source: "ep-03", target: "u-03",  type: "auth",       malicious: false },
    { source: "ep-03", target: "p-03",  type: "spawned",    malicious: false },
    { source: "p-03",  target: "ip-03", type: "connected",  malicious: false },
    { source: "ep-01", target: "p-02",  type: "spawned",    malicious: false },
    { source: "ep-02", target: "ep-01", type: "lateral",    malicious: false },
  ];

  // SHAP-style explanations for the malicious chain
  const SHAP = {
    "p-01": [
      { feature: "encoded_command_length",   value: 0.34, dir: "+" },
      { feature: "parent_is_office_doc",     value: 0.28, dir: "+" },
      { feature: "outbound_connection_to_new_asn", value: 0.21, dir: "+" },
      { feature: "spawned_lolbin_child",     value: 0.13, dir: "+" },
      { feature: "user_in_admin_group",      value: -0.04, dir: "−" },
    ],
    "ip-02": [
      { feature: "domain_age_hours",          value: 0.41, dir: "+" },
      { feature: "tls_ja3_match_known_c2",    value: 0.29, dir: "+" },
      { feature: "beacon_jitter_score",       value: 0.18, dir: "+" },
      { feature: "asn_reputation",            value: 0.09, dir: "+" },
    ],
    "f-02": [
      { feature: "yara_rule_loader_v3",       value: 0.45, dir: "+" },
      { feature: "entropy",                   value: 0.27, dir: "+" },
      { feature: "imports_virtualalloc_writefile", value: 0.16, dir: "+" },
      { feature: "signed",                    value: -0.06, dir: "−" },
    ],
  };

  const RESPONSES = {
    "p-01": [
      { action: "Kill process",        target: "PID 4128 on FIN-WKS-07", risk: "low",  duration: "2s" },
      { action: "Quarantine parent",   target: "invoice_q3.docm",        risk: "low",  duration: "5s" },
      { action: "Isolate endpoint",    target: "FIN-WKS-07",             risk: "med",  duration: "1m" },
    ],
    "ip-02": [
      { action: "Block at firewall",   target: "c2.evilcdn.io / 23.45.x", risk: "low", duration: "3s" },
      { action: "Sinkhole DNS",        target: "*.evilcdn.io",            risk: "low", duration: "10s" },
      { action: "Hunt across fleet",   target: "all endpoints",           risk: "low", duration: "background" },
    ],
    "f-02": [
      { action: "Quarantine file",     target: "C:\\ProgramData\\loader.dll", risk: "low", duration: "2s" },
      { action: "Hash blocklist",      target: "9d11…ca44",                  risk: "low", duration: "5s" },
      { action: "Roll cred for svc_backup", target: "u-02",                   risk: "med", duration: "5m" },
    ],
  };

  const TIMELINE = EDGES.filter(e => e.malicious).map(e => ({
    ts: e.ts, src: e.source, dst: e.target, action: e.type,
  }));

  return { NODES, EDGES, SHAP, RESPONSES, TIMELINE };
})();
