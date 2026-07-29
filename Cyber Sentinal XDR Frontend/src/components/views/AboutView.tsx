// AboutView.tsx
// Product information, architecture overview, detection capabilities, tech stack, and commands reference.

import React, { useState, useCallback } from "react";
import { motion } from "framer-motion";

// ── Section-header label style ────────────────────────────────────────────────
const SECTION_LABEL: React.CSSProperties = {
  fontFamily: "'Fira Code', monospace",
  fontSize: 9,
  fontWeight: 700,
  letterSpacing: 1.8,
  textTransform: "uppercase",
  color: "var(--text-secondary)",
  marginBottom: 16,
};

// ── Panel card base ───────────────────────────────────────────────────────────
function Panel({
  children,
  accent = "#3b82f6",
  style,
}: {
  children: React.ReactNode;
  accent?: string;
  style?: React.CSSProperties;
}) {
  return (
    <div
      style={{
        background: "var(--bg-card)",
        borderLeft: `4px solid ${accent}`,
        borderRadius: 12,
        padding: "24px 28px",
        position: "relative",
        overflow: "hidden",
        ...style,
      }}
    >
      {/* Corner glow */}
      <div
        style={{
          position: "absolute",
          top: -20,
          right: -20,
          width: 80,
          height: 80,
          borderRadius: "50%",
          background: `${accent}0d`,
          pointerEvents: "none",
        }}
      />
      {children}
    </div>
  );
}

// ── Animated architecture flow ────────────────────────────────────────────────
const FLOW_STEPS = [
  { icon: "▣", label: "Endpoints" },
  { icon: "⬡", label: "Data Collection" },
  { icon: "◈", label: "Ingestion API" },
  { icon: "◉", label: "Fusion Engine" },
  { icon: "◬", label: "Alert Generation" },
  { icon: "◫", label: "SOAR Response" },
];

function ArchitectureFlow() {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 0,
        overflowX: "auto",
        paddingBottom: 8,
      }}
    >
      {FLOW_STEPS.map((step, i) => (
        <React.Fragment key={step.label}>
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.12, duration: 0.35 }}
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: 8,
              padding: "16px 18px",
              background: "var(--accent-cyan-dim)",
              border: "1px solid rgba(47,224,224,0.18)",
              borderRadius: 10,
              minWidth: 100,
              flexShrink: 0,
            }}
          >
            <span style={{ fontSize: 22, color: "var(--accent-cyan)" }}>{step.icon}</span>
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                color: "var(--text-secondary)",
                textAlign: "center",
                letterSpacing: 0.5,
              }}
            >
              {step.label}
            </span>
          </motion.div>

          {i < FLOW_STEPS.length - 1 && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                position: "relative",
                width: 40,
                flexShrink: 0,
                overflow: "hidden",
              }}
            >
              {/* Static arrow line */}
              <div
                style={{
                  height: 2,
                  width: "100%",
                  background:
                    "linear-gradient(90deg, rgba(47,224,224,0.30) 0%, var(--border-color) 100%)",
                  position: "relative",
                }}
              />
              {/* Animated flow dot */}
              <motion.div
                animate={{ x: [0, 38, 0] }}
                transition={{
                  duration: 1.8,
                  repeat: Infinity,
                  delay: i * 0.3,
                  ease: "linear",
                }}
                style={{
                  position: "absolute",
                  left: 0,
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--accent-cyan)",
                  boxShadow: "0 0 8px var(--accent-cyan)",
                  top: "50%",
                  transform: "translateY(-50%)",
                }}
              />
              {/* Arrow head */}
              <div
                style={{
                  position: "absolute",
                  right: 0,
                  top: "50%",
                  transform: "translateY(-50%)",
                  width: 0,
                  height: 0,
                  borderTop: "5px solid transparent",
                  borderBottom: "5px solid transparent",
                  borderLeft: "7px solid rgba(47,224,224,0.50)",
                }}
              />
            </div>
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

// ── Detection capabilities matrix ─────────────────────────────────────────────
const DETECTIONS = [
  { attack: "Ransomware",          mitre: "T1486", layer: "System + Malware",  confidence: "HIGH" },
  { attack: "C2 Beaconing",        mitre: "T1071", layer: "Network ML",         confidence: "HIGH" },
  { attack: "Privilege Escalation",mitre: "T1068", layer: "Sysmon",             confidence: "MEDIUM" },
  { attack: "Lateral Movement",    mitre: "T1021", layer: "Network + User",     confidence: "HIGH" },
  { attack: "Port Scan",           mitre: "T1046", layer: "Rule + Network ML",  confidence: "HIGH" },
  { attack: "DDoS",                mitre: "T1498", layer: "Network ML",         confidence: "HIGH" },
  { attack: "Brute Force",         mitre: "T1110", layer: "User Behavior",      confidence: "MEDIUM" },
  { attack: "Infiltration",        mitre: "T1190", layer: "Network ML",         confidence: "HIGH" },
];

const CONF_COLORS: Record<string, string> = {
  HIGH:   "#22c55e",
  MEDIUM: "#f59e0b",
  LOW:    "#ef4444",
};

// ── Tech stack cards ──────────────────────────────────────────────────────────
const TECH_STACK = [
  { name: "FastAPI + Python",          desc: "Backend REST + Socket.IO server",        icon: "⚡", accent: "#3b82f6" },
  { name: "React + TypeScript",        desc: "SOC dashboard — Framer Motion UI",       icon: "⬡", accent: "var(--accent-cyan)" },
  { name: "Scikit-learn / PyTorch",    desc: "IsolationForest, LSTM + Behavioral",     icon: "◈", accent: "#a78bfa" },
  { name: "LightGBM / XGBoost",        desc: "Malware + User Behavior classifiers",    icon: "◉", accent: "#f59e0b" },
  { name: "Suricata + Sysmon",         desc: "Network IDS and host behavior sensors",  icon: "◬", accent: "#ef4444" },
  { name: "Winlogbeat",                desc: "Windows event log shipper",              icon: "◫", accent: "#6b7280" },
  { name: "MongoDB Atlas",             desc: "20 capped collections, real-time writes",icon: "▣", accent: "#22c55e" },
  { name: "SHAP TreeExplainer",        desc: "Feature attribution for all ML models",  icon: "◈", accent: "#f472b6" },
  { name: "Socket.IO",                 desc: "Bi-directional real-time event bus",     icon: "⬣", accent: "var(--accent-cyan)" },
];

// ── Expanded Commands reference ───────────────────────────────────────────────
interface CommandCategory {
  category: string;
  accent: string;
  commands: string;
}

const COMMAND_CATEGORIES: CommandCategory[] = [
  {
    category: "Suricata — Network Monitoring & Configuration",
    accent: "#ef4444",
    commands: `# Start Suricata (run as Administrator)
& "C:\\Program Files\\Suricata\\suricata.exe" -c "C:\\Program Files\\Suricata\\suricata.yaml" -i "\\Device\\NPF_{B5A75558-6CB6-473B-B521-5B390F7ADE47}" -l "C:\\SuricataLogs"

# Test Suricata config
& "C:\\Program Files\\Suricata\\suricata.exe" -T -c "C:\\Program Files\\Suricata\\suricata.yaml"

# Update Suricata rules
suricata-update

# Check Suricata logs (live tail)
Get-Content "C:\\SuricataLogs\\eve.json" -Tail 50 -Wait

# Collect network baseline (30-60 min)
python collect_baseline.py

# Train network ML models
python train_model.py            # IsolationForest anomaly detector
python train_classifier.py       # RandomForest attack classifier (CIC-IDS2017)
python train_personal_model.py   # Personal baseline IsolationForest`,
  },
  {
    category: "System Behavior — Sysmon & System Monitor",
    accent: "#f59e0b",
    commands: `# Install Sysmon (run as Administrator)
.\\Sysmon64.exe -accepteula -i sysmon-config.xml

# Update Sysmon config
.\\Sysmon64.exe -c sysmon-config.xml

# Check Sysmon service status
Get-Service -Name Sysmon64

# Train System Monitor LSTM model
python train_system_model.py --collect-minutes 60

# Start XDR Backend (monitors system in background)
cd "D:\\Cyber Sentinal\\Backend"
.\\venv\\Scripts\\activate
uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload

# View Sysmon event log (live tail)
Get-Content "C:\\winlogbeat\\logs\\sysmon_events.json" -Tail 50`,
  },
  {
    category: "User Behavior — Winlogbeat & OC-SVM",
    accent: "#a78bfa",
    commands: `# Install Winlogbeat as service (run as Administrator)
cd "C:\\Program Files\\Winlogbeat"
.\\install-service-winlogbeat.ps1

# Start / Stop / Restart Winlogbeat
Start-Service winlogbeat
Stop-Service winlogbeat
Restart-Service winlogbeat

# Check Winlogbeat status
Get-Service winlogbeat

# View Winlogbeat output logs (live tail)
Get-Content "C:\\XDR_Logs\\winlogbeat.json" -Tail 50 -Wait

# Test user behavior model
python "User Behavior\\final_model_backend_only\\test_model_realtime.py"

# Verify feature extraction
python -c "import json; d=json.load(open('User Behavior/final_model_backend_only/feature_columns.json')); print(d)"`,
  },
  {
    category: "Malware Detection — EMBER & LightGBM",
    accent: "#f472b6",
    commands: `# Train malware model (requires EMBER dataset)
python train_malware_model.py

# Scan a specific file
curl -X POST http://localhost:8000/scan/malware \`
  -H "X-API-Key: YOUR_KEY" \`
  -H "Content-Type: application/json" \`
  -d '{"file_path": "C:\\\\path\\\\to\\\\file.exe"}'

# Predict from existing PE features
curl -X POST http://localhost:8000/predict/malware \`
  -H "X-API-Key: YOUR_KEY" \`
  -H "Content-Type: application/json" \`
  -d '{"file_path": "C:\\\\Windows\\\\System32\\\\notepad.exe"}'

# View malware scan results in MongoDB
# mongosh --eval "db.malware_scans.find().sort({timestamp:-1}).limit(10).pretty()"`,
  },
  {
    category: "Endpoint Agent — Deployment & Management",
    accent: "var(--accent-cyan)",
    commands: `# Install endpoint agent dependencies
pip install httpx>=0.27.0 psutil>=5.9.0

# Run endpoint agent
python agent.py --backend http://SERVER_IP:8000 --api-key YOUR_KEY

# Dry-run simulation (no data sent)
python agent.py --simulate

# Environment variable configuration
$env:XDR_BACKEND_URL = "http://192.168.1.100:8000"
$env:XDR_API_KEY     = "your-api-key"
$env:XDR_COLLECT_INTERVAL = "5"
$env:XDR_COMMAND_INTERVAL = "3"

# Install as Windows Service (using NSSM)
nssm install XDRAgent python "D:\\endpoint_agent\\agent.py"
nssm set XDRAgent AppEnvironmentExtra XDR_BACKEND_URL=http://SERVER:8000
nssm start XDRAgent`,
  },
  {
    category: "Prevention & Response — SOAR Actions",
    accent: "#dc2626",
    commands: `# Isolate a host (disable network interface)
netsh interface set interface "Wi-Fi" disable

# Re-enable / unisolate host
netsh interface set interface "Wi-Fi" enable

# Block a specific IP address
netsh advfirewall firewall add rule name="XDR_BLOCK_192.168.1.100" \`
  dir=out action=block remoteip=192.168.1.100

# Unblock an IP address
netsh advfirewall firewall delete rule name="XDR_BLOCK_192.168.1.100"

# Kill a process by name
Stop-Process -Name "malware.exe" -Force

# Kill a process by PID
Stop-Process -Id 1234 -Force

# Quarantine a file (move to safe location)
Move-Item "C:\\path\\to\\suspect.exe" "D:\\Cyber Sentinal\\Backend\\quarantine\\"

# View active XDR firewall block rules
netsh advfirewall firewall show rule name=all | Select-String "XDR_BLOCK"

# Issue SOAR command via API
curl -X POST http://localhost:8000/endpoint/command \`
  -H "Authorization: Bearer YOUR_JWT" \`
  -H "Content-Type: application/json" \`
  -d '{"endpoint_id":"TARGET_ID","action":"isolate_host","target":""}'`,
  },
  {
    category: "MongoDB — Database Management",
    accent: "#22c55e",
    commands: `# Start MongoDB
& "C:\\Program Files\\MongoDB\\Server\\8.0\\bin\\mongod.exe" \`
  --dbpath "D:\\Cyber Sentinal\\mongodb\\data" --port 27017

# Connect to MongoDB shell
mongosh --port 27017

# View recent fusion alerts
# db.fused_alerts.find().sort({timestamp:-1}).limit(10).pretty()

# View endpoint registry
# db.endpoint_registry.find().pretty()

# View critical alerts (permanent store)
# db.critical_alerts.find().sort({timestamp:-1}).limit(20).pretty()

# Clear old endpoint logs manually
# db.endpoint_logs.deleteMany({timestamp: {$lt: new Date(Date.now()-86400000*90)}})`,
  },
  {
    category: "ML Training Pipeline — Full Setup",
    accent: "#3b82f6",
    commands: `# Step 1: Capture normal baseline traffic (run while doing normal work)
python collect_baseline.py       # 30-60 min

# Step 2: Train personal IsolationForest baseline
python train_personal_model.py

# Step 3: Train CIC-IDS2017 network models
python train_model.py            # Anomaly detector
python train_classifier.py       # Attack classifier

# Step 4: Train System Monitor LSTM
python train_system_model.py --collect-minutes 60

# Step 5: Train malware classifier (needs EMBER dataset)
python train_malware_model.py

# Verify all model artifacts exist
ls Backend\\*.pkl
ls Backend\\*.pt`,
  },
];

// ── Planned upgrade cards ─────────────────────────────────────────────────────
interface UpgradeCard {
  icon: string;
  title: string;
  description: string;
  accent: string;
  mitre?: string;
}

const PLANNED_UPGRADES: UpgradeCard[] = [
  {
    icon: "🔒",
    title: "Session Token Security",
    description:
      "JWT tokens are currently stored in localStorage for development convenience. Production deployment will migrate to httpOnly cookies with CSRF token validation, eliminating XSS-based token extraction vectors.",
    accent: "#f59e0b",
    mitre: "Defense Evasion — T1550.001",
  },
  {
    icon: "👤",
    title: "Behavioral Personality Profiling",
    description:
      "OCEAN personality dimensions (Openness, Conscientiousness, Extraversion, Agreeableness, Neuroticism) are currently derived from behavioral heuristics. Full enrichment requires integration with an HR profile feed or Active Directory attributes for per-user baseline personalization.",
    accent: "#f59e0b",
  },
];

// ── Accordion command block ───────────────────────────────────────────────────
function AccordionCommandBlock({ category, accent, commands }: CommandCategory) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopyAll = useCallback(() => {
    navigator.clipboard.writeText(commands).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }, [commands]);

  return (
    <div
      style={{
        background: "var(--bg-primary)",
        border: `1px solid ${open ? accent + "44" : "var(--border-color)"}`,
        borderRadius: 10,
        overflow: "hidden",
        transition: "border-color 0.2s",
      }}
    >
      {/* Accordion header */}
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          width: "100%",
          background: open ? `${accent}10` : "transparent",
          border: "none",
          borderBottom: open ? `1px solid ${accent}22` : "none",
          padding: "12px 16px",
          display: "flex",
          alignItems: "center",
          gap: 10,
          cursor: "pointer",
          textAlign: "left",
          transition: "background 0.2s",
        }}
      >
        <span
          style={{
            display: "inline-block",
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: accent,
            boxShadow: open ? `0 0 8px ${accent}` : "none",
            flexShrink: 0,
            transition: "box-shadow 0.2s",
          }}
        />
        <span
          style={{
            flex: 1,
            fontFamily: "'Fira Code', monospace",
            fontSize: 11,
            fontWeight: 700,
            color: open ? accent : "var(--text-muted)",
            letterSpacing: 0.5,
            transition: "color 0.2s",
          }}
        >
          {category}
        </span>
        <span
          style={{
            color: open ? accent : "var(--text-muted)",
            fontSize: 12,
            fontWeight: 700,
            transform: open ? "rotate(180deg)" : "rotate(0deg)",
            transition: "transform 0.2s, color 0.2s",
            display: "inline-block",
          }}
        >
          ▾
        </span>
      </button>

      {/* Expanded content */}
      {open && (
        <div style={{ position: "relative" }}>
          {/* Copy All button */}
          <button
            onClick={handleCopyAll}
            style={{
              position: "absolute",
              top: 10,
              right: 14,
              background: copied ? `${accent}22` : "var(--bg-secondary)",
              border: `1px solid ${copied ? accent : "var(--border-color)"}`,
              borderRadius: 6,
              padding: "4px 10px",
              cursor: "pointer",
              color: copied ? accent : "var(--text-secondary)",
              fontFamily: "'Fira Code', monospace",
              fontSize: 10,
              fontWeight: 700,
              zIndex: 2,
              transition: "all 0.15s",
              whiteSpace: "nowrap",
            }}
          >
            {copied ? "Copied!" : "Copy All"}
          </button>

          {/* Code block */}
          <pre
            style={{
              margin: 0,
              padding: "16px 14px 16px 14px",
              paddingRight: 100,
              fontFamily: "'Fira Code', 'Courier New', monospace",
              fontSize: 11,
              lineHeight: 1.7,
              color: "#22c55e",
              background: "var(--bg-primary)",
              overflowX: "auto",
              whiteSpace: "pre",
            }}
          >
            {commands.split("\n").map((line, i) => {
              const isComment = line.trimStart().startsWith("#");
              return (
                <span
                  key={i}
                  style={{
                    display: "block",
                    color: isComment ? "var(--text-secondary)" : "#86efac",
                  }}
                >
                  {line || " "}
                </span>
              );
            })}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function AboutView() {
  return (
    // Outer wrapper: fills its parent height and scrolls internally
    <div
      style={{
        height: "100%",
        overflowY: "auto",
        overflowX: "hidden",
      }}
    >
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.28 }}
        style={{
          padding: 24,
          maxWidth: 1100,
          margin: "0 auto",
          display: "flex",
          flexDirection: "column",
          gap: 24,
          // Ensure the animated div doesn't constrain the scroll container
          minHeight: "min-content",
        }}
      >
        {/* ── A. Hero ────────────────────────────────────────────────────────── */}
        <Panel accent="var(--accent-cyan)" style={{ textAlign: "center", padding: "40px 28px" }}>
          {/* Logo */}
          <div style={{ display: "flex", justifyContent: "center", marginBottom: 20 }}>
            <div style={{
              width: 110,
              height: 110,
              borderRadius: 22,
              overflow: "hidden",
              background: "#070c18",
              border: "2px solid rgba(47,224,224,0.35)",
              boxShadow: "0 0 32px rgba(47,224,224,0.30), 0 0 8px var(--border-color-strong)",
            }}>
              <img
                src="/logo.jpg"
                alt="Cyber Sentinel XDR Logo"
                style={{ width: "100%", height: "100%", objectFit: "cover", display: "block" }}
              />
            </div>
          </div>
          <div
            style={{
              fontSize: 11,
              fontFamily: "'Fira Code', monospace",
              fontWeight: 700,
              letterSpacing: 4,
              color: "var(--accent-cyan)",
              marginBottom: 12,
              textTransform: "uppercase",
            }}
          >
            v1.0 — Enterprise XDR Platform
          </div>
          <h1
            style={{
              margin: "0 0 10px",
              fontSize: 34,
              fontWeight: 900,
              color: "var(--text-primary)",
              letterSpacing: -1,
            }}
          >
            CYBER SENTINEL XDR
          </h1>
          <p
            style={{
              margin: "0 0 20px",
              color: "var(--text-muted)",
              fontSize: 14,
              maxWidth: 600,
              marginLeft: "auto",
              marginRight: "auto",
            }}
          >
            Multi-Domain Detection &amp; Response Platform — enterprise-grade threat
            detection powered by ML fusion across network, system, user behavior, and
            malware analysis layers.
          </p>

          {/* Capability pills */}
          <div style={{ display: "flex", gap: 10, justifyContent: "center", flexWrap: "wrap" }}>
            {["Real-Time Detection", "AI-Powered Fusion", "Automated Response"].map((pill) => (
              <span
                key={pill}
                style={{
                  padding: "6px 16px",
                  borderRadius: 20,
                  border: "1px solid rgba(47,224,224,0.35)",
                  background: "var(--accent-cyan-dim)",
                  color: "var(--accent-cyan)",
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: 0.5,
                }}
              >
                {pill}
              </span>
            ))}
          </div>
        </Panel>

        {/* ── B. Architecture Flow ─────────────────────────────────────────── */}
        <Panel accent="#3b82f6">
          <div style={SECTION_LABEL}>Architecture Flow</div>
          <ArchitectureFlow />
        </Panel>

        {/* ── C. Detection Capabilities Matrix ────────────────────────────── */}
        <Panel accent="#ef4444">
          <div style={SECTION_LABEL}>MITRE ATT&amp;CK Coverage</div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr>
                  {["Attack Type", "MITRE ID", "Detection Layer", "Confidence"].map((h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: "left",
                        padding: "8px 12px",
                        borderBottom: "1px solid var(--border-color)",
                        color: "var(--text-secondary)",
                        fontWeight: 700,
                        fontSize: 10,
                        letterSpacing: 1,
                        textTransform: "uppercase",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {DETECTIONS.map((row, i) => (
                  <tr
                    key={row.mitre}
                    style={{
                      background: i % 2 === 0 ? "rgba(0,0,0,0.15)" : "transparent",
                    }}
                  >
                    <td
                      style={{
                        padding: "10px 12px",
                        color: "var(--text-primary)",
                        fontWeight: 600,
                      }}
                    >
                      {row.attack}
                    </td>
                    <td
                      style={{
                        padding: "10px 12px",
                        fontFamily: "'Fira Code', monospace",
                        color: "#a78bfa",
                        fontSize: 11,
                      }}
                    >
                      {row.mitre}
                    </td>
                    <td style={{ padding: "10px 12px", color: "var(--text-secondary)" }}>{row.layer}</td>
                    <td style={{ padding: "10px 12px" }}>
                      <span
                        style={{
                          padding: "2px 10px",
                          borderRadius: 12,
                          background: `${CONF_COLORS[row.confidence] ?? "#6b7280"}1a`,
                          color: CONF_COLORS[row.confidence] ?? "#6b7280",
                          border: `1px solid ${CONF_COLORS[row.confidence] ?? "#6b7280"}44`,
                          fontSize: 10,
                          fontWeight: 700,
                          letterSpacing: 0.5,
                        }}
                      >
                        {row.confidence}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        {/* ── D. Tech Stack ───────────────────────────────────────────────── */}
        <Panel accent="#a78bfa">
          <div style={SECTION_LABEL}>Technology Stack</div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
              gap: 12,
            }}
          >
            {TECH_STACK.map((tech) => (
              <div
                key={tech.name}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 12,
                  padding: "14px 16px",
                  background: "var(--bg-primary)",
                  border: `1px solid ${tech.accent}22`,
                  borderRadius: 10,
                }}
              >
                <span
                  style={{
                    fontSize: 20,
                    color: tech.accent,
                    lineHeight: 1,
                    flexShrink: 0,
                    marginTop: 2,
                  }}
                >
                  {tech.icon}
                </span>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: "var(--text-primary)" }}>
                    {tech.name}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 3 }}>
                    {tech.desc}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Panel>

        {/* ── E. Expanded Commands Reference ─────────────────────────────── */}
        <Panel accent="#22c55e">
          <div style={SECTION_LABEL}>Interactive Commands Reference</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {COMMAND_CATEGORIES.map((block) => (
              <AccordionCommandBlock key={block.category} {...block} />
            ))}
          </div>
        </Panel>

        {/* ── F. Planned Upgrades ─────────────────────────────────────────── */}
        <Panel accent="#f59e0b">
          <div style={SECTION_LABEL}>Future Roadmap</div>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
              gap: 12,
            }}
          >
            {PLANNED_UPGRADES.map((card, i) => (
              <motion.div
                key={card.title}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1, duration: 0.3 }}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 10,
                  padding: "16px 18px",
                  background: "var(--bg-primary)",
                  border: `1px solid ${card.accent}22`,
                  borderRadius: 10,
                  position: "relative",
                  overflow: "hidden",
                }}
              >
                {/* Corner glow */}
                <div
                  style={{
                    position: "absolute",
                    top: -16,
                    right: -16,
                    width: 60,
                    height: 60,
                    borderRadius: "50%",
                    background: `${card.accent}0d`,
                    pointerEvents: "none",
                  }}
                />

                {/* Header row: icon + title + PLANNED badge */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                  }}
                >
                  <span
                    style={{
                      fontSize: 20,
                      lineHeight: 1,
                      flexShrink: 0,
                    }}
                  >
                    {card.icon}
                  </span>
                  <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-primary)", flex: 1 }}>
                    {card.title}
                  </div>
                  <span
                    style={{
                      padding: "2px 10px",
                      borderRadius: 12,
                      background: `${card.accent}1a`,
                      color: card.accent,
                      border: `1px solid ${card.accent}44`,
                      fontSize: 9,
                      fontWeight: 700,
                      letterSpacing: 1,
                      textTransform: "uppercase" as const,
                      flexShrink: 0,
                    }}
                  >
                    PLANNED
                  </span>
                </div>

                {/* Description */}
                <div
                  style={{
                    fontSize: 11,
                    color: "var(--text-secondary)",
                    lineHeight: 1.65,
                  }}
                >
                  {card.description}
                </div>

                {/* Optional MITRE reference */}
                {card.mitre && (
                  <div
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6,
                      marginTop: 2,
                    }}
                  >
                    <span
                      style={{
                        fontFamily: "'Fira Code', monospace",
                        fontSize: 9,
                        fontWeight: 700,
                        color: "#a78bfa",
                        letterSpacing: 0.5,
                      }}
                    >
                      {card.mitre}
                    </span>
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </Panel>

        {/* ── G. Version + Credits ────────────────────────────────────────── */}
        <Panel accent="#f59e0b">
          <div style={SECTION_LABEL}>Version &amp; Credits</div>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: 32,
              alignItems: "flex-start",
            }}
          >
            <div style={{ flex: 1, minWidth: 200 }}>
              <div
                style={{
                  fontSize: 18,
                  fontWeight: 800,
                  color: "var(--text-primary)",
                  marginBottom: 6,
                }}
              >
                v1.0 XDR Platform
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>
                2026 — All rights reserved
              </div>
              <div
                style={{
                  fontSize: 12,
                  color: "var(--text-secondary)",
                  marginBottom: 4,
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <span style={{ color: "var(--accent-amber)" }}>◈</span>
                System Architect: Annas Habib
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 8, lineHeight: 1.6 }}>
                Inspired by enterprise-grade XDR architectures including CrowdStrike
                Falcon and Microsoft Sentinel.
              </div>
            </div>

            {/* Stats */}
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              {[
                { label: "Models Trained", value: "5" },
                { label: "Detection Layers", value: "6" },
                { label: "MITRE Techniques", value: "8+" },
                { label: "MongoDB Collections", value: "20" },
              ].map((stat) => (
                <div
                  key={stat.label}
                  style={{
                    background: "var(--bg-primary)",
                    border: "1px solid var(--border-color)",
                    borderRadius: 10,
                    padding: "16px 20px",
                    textAlign: "center",
                    minWidth: 100,
                  }}
                >
                  <div
                    style={{
                      fontSize: 26,
                      fontWeight: 900,
                      color: "var(--accent-amber)",
                      lineHeight: 1,
                    }}
                  >
                    {stat.value}
                  </div>
                  <div
                    style={{
                      fontSize: 9,
                      fontWeight: 700,
                      color: "var(--text-secondary)",
                      textTransform: "uppercase",
                      letterSpacing: 1,
                      marginTop: 6,
                    }}
                  >
                    {stat.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Panel>

        {/* bottom padding so last card isn't flush against scroll boundary */}
        <div style={{ height: 16 }} />
      </motion.div>
    </div>
  );
}
