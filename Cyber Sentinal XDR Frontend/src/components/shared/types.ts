// Shared TypeScript types for Cyber Sentinel XDR Dashboard

export interface Top3 {
  type: string;
  confidence: number;
}

export interface RawFlowPayload {
  cycle: number;
  timestamp: string;
  ts?: string;          // backend alias for timestamp (used in monitoring-loop emits)
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  network_transport: string;
  network_protocol: string;
  network_direction: string;
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  connection_duration: number;
  connection_count: number;
  unique_dst_ips: number;
  unique_dst_ports: number;
  failed_connection_ratio: number;
  anomaly_score: number;
  confidence: number;
  prediction: "ANOMALY" | "NORMAL";
  severity: "LOW" | "MEDIUM" | "HIGH";
  attack_type?: string | null;
  attack_confidence?: number | null;
  traffic_label?: string;
  traffic_icon?: string;
  traffic_description?: string;
  traffic_category?: "ATTACK" | "NORMAL";
}

export interface FlowResult {
  cycle: number;
  timestamp: string;
  src_ip: string;
  dest_ip: string;
  src_port: number;
  dest_port: number;
  protocol: string;
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  flow_duration: number;
  flow_bytes_per_s: number;
  prediction: "ATTACK" | "NORMAL";
  attack_type: string;
  confidence: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  color: string;
  icon: string;
  description: string;
  top3: Top3[];
  traffic_label: string;
  traffic_icon: string;
  traffic_description: string;
  traffic_category: "ATTACK" | "NORMAL";
}

export interface StatusEvent {
  status: string;
  message: string;
  cycle?: number;
  total_flows?: number;
  attack_count?: number;
  attack_breakdown?: Record<string, number>;
  // Suricata diagnostics — populated by the monitoring_status socket event
  zero_flow_cycles?: number;
  suricata_eve_exists?: boolean;
  suricata_eve_bytes?: number;
  network_active?: boolean;
}

/**
 * Payload shape for the `system_anomaly` Socket.IO event.
 * The backend System Monitor emits this from the LSTM Autoencoder path.
 * When the behavioral detector (DETECTOR1 / detector.pkl) also fires,
 * the four `behavioral_*` fields are included alongside the LSTM fields.
 */
export interface SystemAnomalyEvent {
  ts?: string;
  source?: string;
  anomaly_score: number;
  score?: number;
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  is_genuinely_anomalous?: boolean;
  features_snapshot?: number[];
  shap_reasons?: string[];
  shap_explanation?: string[];
  // Behavioral detector fields — present only when the process-behavior model fires
  behavioral_score?: number;
  behavioral_attack_type?: string;
  behavioral_confidence?: number;
  behavioral_is_anomaly?: boolean;
}

export interface Stats {
  total: number;
  attacks: number;
  normal: number;
  cycles: number;
}

export interface UserAnomalyRow {
  user: string;
  anomaly_score?: number;
  prediction_label?: string;
  after_hours_logins?: number;
  usb_connects?: number;
  files_accessed?: number;
  unique_files?: number;
  emails_sent?: number;
  total_logins?: number;
  ts?: string;
  fusion?: { threat_score?: number; severity?: string };
  // Endpoint telemetry source fields (present when source === "endpoint")
  endpoint_id?: string;
  hostname?: string;
  source?: string;
  // Alarm snooze state (set server-side via POST /user-behavior/snooze)
  snoozed?: boolean;
  snooze_remaining_s?: number;
  // SHAP explanation strings (when shap_agent runs on user anomaly)
  shap_explanation?: string[];
  // Endpoint-agent specific fields (from UserBehaviorAgent.score_session_telemetry)
  current_user?: string;
  concurrent_sessions?: number;
  unusual_hour?: number;          // 1.0 = after-hours, 0.0 = normal hours
  has_remote_session?: number;    // 1.0 = yes, 0.0 = no
  is_machine_account?: number;    // 1.0 = yes (computer account), 0.0 = no
  user_score?: number;            // raw score 0-1 from UserBehaviorAgent
}

export interface UserBehaviorSummary {
  total_users?: number;
  normal_users?: number;
  anomaly_users?: number;
  avg_score?: number;
  cycle_ts?: string;
  /** All processed users from the latest xdr_runtime cycle (anomalous AND normal) */
  users?: UserAnomalyRow[];
}

export interface SystemHealth {
  status: string;
  mongodb?: string;
  suricata?: string;
  winlogbeat?: string;
  network_agent?: string;
  user_agent?: string;
  fusion_engine?: string;
  shap_agent?: string;
  uptime?: number;
}

export interface StorageStatus {
  total_documents?: number;
  collections?: Record<string, number>;
  storage_full?: boolean;
}

export interface MalwareAlert {
  // New contract fields (backend v2)
  label?: "benign" | "suspicious" | "malicious";
  trusted?: boolean;
  trust_reason?: string;
  confidence?: number;
  source?: string;
  // prediction kept as string for backward compatibility — may be
  // "MALWARE" | "BENIGN" | "UNKNOWN" (old) or "BENIGN" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN" (new)
  prediction: string;
  score: number;
  file_path: string;
  file_size: number;
  reason: string;
  host: string;
  ts: string;
  fusion?: {
    attack_type?: string | null;
    threat_score: number;
    severity: string;
    should_respond: boolean;
  };
  shap_explanation?: {
    model: string;
    prediction: string;
    top_features: Array<{ feature: string; shap_value: number; direction: string }>;
    reason: string[];
  };
}

export interface FusionAlert {
  threat_score: number;
  severity: string;
  should_respond: boolean;
  source: string;
  ts: string;
  contributing_models?: string[];
  contributing_reasons?: string[];
}

export interface MalwareSummary {
  total_scanned: number;
  malware_count: number;
  benign_count: number;
  unknown_count: number;
  last_scan_ts: string | null;
}

export interface SocAlert {
  timestamp: string;
  host: string;
  final_severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  mitre_id: string;
  attack_type: string;
  involved_sources: string[];
  final_decision: {
    threat_score: number;
    severity: string;
    should_respond: boolean;
    primary_threat: string;
    mitre_id: string;
    timestamp: string;
    sources_active: string[];
  };
  correlation: {
    attack_detected: boolean;
    attack_chain: boolean;
    attack_type: string;
    mitre_id: string;
    mitre_tactic: string;
    involved_sources: string[];
    involved_hosts: string[];
    confidence: number;
    final_severity: string;
    event_count: number;
    time_span_seconds: number;
    response_suggestions: string[];
  };
  alerts: Array<{
    source: string;
    timestamp: string;
    host: string;
    severity: string;
    confidence: number;
    prediction: string;
  }>;
}

// ── Endpoint Management types ─────────────────────────────────────────────────

export interface EndpointInfo {
  endpoint_id: string;
  hostname: string;
  ip_address: string;
  os: string;
  username: string;
  status: 'online' | 'offline' | 'isolated';
  last_seen: string;
  agent_version: string;
  // live telemetry (from endpoint_update socket event)
  cpu?: number;
  memory?: number;
  // server host flag (set by backend for server_host pre-registration)
  is_server?: boolean;
  // SOAR-applied state (populated from endpoint_registry after command ACK)
  blocked_ips?: string[];
}

export interface TimelineEntry {
  timestamp: string;
  cpu: number;
  memory: number;
  connections: number;
  threat_score: number;
  severity: string;
}

export interface EndpointTimeline {
  endpoint_id: string;
  timeline: TimelineEntry[];
}

export interface EndpointFusionAlert {
  endpoint_id: string;
  threat_score: number;
  severity: string;
  sources: string[];
  attack_type: string;
  shap_explanation?: string[];
}

export interface EndpointAlert {
  endpoint_id: string;
  hostname: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason: string;
  timestamp: string;
}

export interface EndpointCommand {
  command_id?: string;
  endpoint_id: string;
  action: 'kill_process' | 'block_ip' | 'unblock_ip' | 'isolate_host' | 'unisolate_host' | 'quarantine_file' | 'restore_quarantine_file' | 'lock_account' | 'unlock_account' | 'scan_filesystem' | 'monitor_persistence' | 'shutdown_host' | 'sleep_host';
  target: string;
  parameters?: Record<string, string>;
  issued_by?: string;
}

export interface CommandResult {
  command_id: string;
  endpoint_id: string;
  success: boolean;
  message: string;
  /** Action name — present on endpoint_command_status events */
  action?: string;
  /** ISO timestamp — present on endpoint_command_status events */
  timestamp?: string;
  /** Target of the command (IP, process name, file path, etc.) */
  target?: string;
  /** String status from the backend payload: completed | failed | sent | pending */
  status?: string;
  /** Full result message from endpoint ACK */
  result_message?: string;
}

// Constants
export const SEVERITY_COLOUR: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH:     "#ea580c",
  MEDIUM:   "#d97706",
  LOW:      "#22c55e",
};

export const ATTACK_COLOURS: Record<string, string> = {
  BENIGN:       "#22c55e",
  DoS:          "#dc2626",
  DDoS:         "#7f1d1d",
  PortScan:     "#ea580c",
  BruteForce:   "#d97706",
  WebAttack:    "#9333ea",
  Botnet:       "#be123c",
  Heartbleed:   "#991b1b",
  Infiltration: "#4c0519",
  Unknown:      "#6b7280",
};

export const ATTACK_ICONS: Record<string, string> = {
  DoS:          "explosive",
  DDoS:         "wave",
  PortScan:     "scan",
  BruteForce:   "hammer",
  WebAttack:    "spider",
  Botnet:       "bot",
  Heartbleed:   "drop",
  Infiltration: "ninja",
  BENIGN:       "check",
  Unknown:      "question",
};

// Helpers
export const fmtBytes = (b: number | undefined | null): string => {
  const n = b ?? 0;
  return n > 1_048_576
    ? `${(n / 1_048_576).toFixed(1)}MB`
    : n > 1024
    ? `${(n / 1024).toFixed(1)}KB`
    : `${n}B`;
};

export const fmtTime = (ts: string): string => {
  if (!ts) return "—";
  try {
    // Python datetime strings use a space separator ("2026-05-04 15:36:21").
    // Replace the space with 'T' so JS Date can parse it as ISO 8601.
    const iso = ts.replace(" ", "T").replace(/(\.\d{3})\d+$/, "$1");
    const d = new Date(iso);
    return isNaN(d.getTime()) ? ts : d.toLocaleTimeString();
  } catch {
    return ts;
  }
};

export function mapRawToFlow(raw: RawFlowPayload): FlowResult {
  const totalBytes = (raw.bytes_sent ?? 0) + (raw.bytes_received ?? 0);
  const duration =
    raw.connection_duration != null && raw.connection_duration > 0
      ? raw.connection_duration
      : 0.000001;
  const flowBytesPerSec = totalBytes / duration;

  const isAttack = raw.prediction === "ANOMALY";
  const attackType =
    raw.attack_type && raw.attack_type !== "BENIGN" ? raw.attack_type : "BENIGN";

  let severity: FlowResult["severity"] = "LOW";
  if (isAttack) {
    if (raw.confidence >= 90 || raw.severity === "HIGH") {
      severity = "CRITICAL";
    } else if (raw.severity === "MEDIUM") {
      severity = "MEDIUM";
    } else {
      severity = "HIGH";
    }
  }

  const color = ATTACK_COLOURS[attackType] ?? (isAttack ? "#ef4444" : "#22c55e");

  const clsConf = raw.attack_confidence ?? raw.confidence ?? 0;
  const top3: Top3[] = isAttack
    ? [
        { type: attackType, confidence: clsConf },
        { type: "BENIGN", confidence: Math.max(0, 100 - clsConf) },
      ]
    : [{ type: "BENIGN", confidence: 100 - Math.min(100, clsConf) }];

  const attackIconMap: Record<string, string> = {
    DoS: "💥", DDoS: "🌊", PortScan: "🔍", BruteForce: "🔨",
    WebAttack: "🕷️", Botnet: "🤖", Heartbleed: "🩸", Infiltration: "🥷",
    BENIGN: "✅", Unknown: "❓",
  };
  const icon = attackIconMap[attackType] ?? (isAttack ? "🚨" : "✅");

  return {
    cycle: raw.cycle,
    timestamp: raw.timestamp ?? raw.ts ?? "",
    src_ip: raw.source_ip,
    dest_ip: raw.destination_ip,
    src_port: raw.source_port,
    dest_port: raw.destination_port,
    protocol: raw.network_protocol ?? raw.network_transport,
    bytes_sent: raw.bytes_sent ?? 0,
    bytes_received: raw.bytes_received ?? 0,
    packets_sent: raw.packets_sent ?? 0,
    packets_received: raw.packets_received ?? 0,
    flow_duration: raw.connection_duration ?? 0,
    flow_bytes_per_s: flowBytesPerSec,
    prediction: isAttack ? "ATTACK" : "NORMAL",
    attack_type: attackType,
    confidence: clsConf,
    severity,
    color,
    icon,
    description:
      raw.traffic_description ||
      (isAttack ? `${attackType}-like behaviour detected` : "Flow considered normal"),
    top3,
    traffic_label: raw.traffic_label || (isAttack ? attackType : "Network Traffic"),
    traffic_icon: raw.traffic_icon || (isAttack ? "🚨" : "📶"),
    traffic_description:
      raw.traffic_description ||
      (isAttack ? `${attackType}-like behaviour detected` : "Normal traffic"),
    traffic_category: raw.traffic_category || (isAttack ? "ATTACK" : "NORMAL"),
  };
}
