// NetworkMonitor.tsx
// Top-level SOC Dashboard layout — sidebar + active view
// Socket events: "network" | "monitoring_status" | "user_anomaly" | "user_behavior_summary"

import React, { useState, useEffect, useRef, useCallback } from "react";
import axios from "axios";
import { io, Socket } from "socket.io-client";
import { motion, AnimatePresence } from "framer-motion";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { useSirenAudio } from "../hooks/useSirenAudio";

import Sidebar, { ViewId } from "./shared/Sidebar";
import { AttackGraphView } from "./views/AttackGraphView";
import OverviewView from "./views/OverviewView";
import NetworkView from "./views/NetworkView";
import UserBehaviorView from "./views/UserBehaviorView";
import AlertsView from "./views/AlertsView";
import EndpointView from "./views/EndpointView";
import EndpointDetailView from "./views/EndpointDetailView";
import SystemStatusView from "./views/SystemStatusView";
import MalwareView from "./views/MalwareView";
import SysmonBehaviorView from "./views/SysmonBehaviorView";
import AboutView from "./views/AboutView";
import SettingsView from "./views/SettingsView";
import ProfileView from "./views/ProfileView";
import AttackReconstructionView from "./views/AttackReconstructionView";
import AlertSiren from "./AlertSiren";
import AuditLogPanel from "./AuditLogPanel";

import {
  RawFlowPayload,
  FlowResult,
  StatusEvent,
  Stats,
  UserAnomalyRow,
  UserBehaviorSummary,
  MalwareAlert,
  MalwareSummary,
  FusionAlert,
  SocAlert,
  EndpointInfo,
  EndpointAlert,
  EndpointCommand,
  CommandResult,
  EndpointFusionAlert,
  mapRawToFlow,
} from "./shared/types";
import { ResponsePlan, IncidentReport } from "./shared/responseTypes";
import { SysmonBehaviorAlert } from "./views/SysmonBehaviorView";
import { useAuth } from "../context/AuthContext";
import { authAxios } from "../services/authService";
import { BACKEND_URL } from "../config";
const MAX_TABLE_ROWS = 100;
const MAX_CHART_POINTS = 30;

// Extended ViewId to include views not in Sidebar's ViewId
type ExtViewId = ViewId | "attack-reconstruction";

// A single decoy-port honeypot hit, flattened for the deception panel.
export interface HoneypotHit {
  endpoint_id: string;
  hostname?: string;
  decoy_port?: number;
  service?: string;
  attacker_ip?: string;
  attacker_port?: number;
  data_preview?: string;
  count?: number;
  timestamp?: string;
  last_seen?: string;
}

export default function NetworkMonitor() {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  // ── View state ───────────────────────────────────────────────────────────────
  const [activeView, setActiveView] = useState<ExtViewId>("overview");

  // ── Monitoring state ─────────────────────────────────────────────────────────
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<StatusEvent>({
    status: "idle",
    message: "Ready to start monitoring",
  });

  // Ref gives socket handlers access to current isMonitoring without stale closure
  const isMonitoringRef = useRef(false);
  useEffect(() => { isMonitoringRef.current = isMonitoring; }, [isMonitoring]);

  // ── Data state ───────────────────────────────────────────────────────────────
  const [flows, setFlows] = useState<FlowResult[]>([]);
  const [stats, setStats] = useState<Stats>({ total: 0, attacks: 0, normal: 0, cycles: 0 });
  const [timelineData, setTimelineData] = useState<{ time: string; attacks: number; normal: number }[]>([]);
  const [attackTypeData, setAttackTypeData] = useState<Record<string, number>>({});
  const [severityData, setSeverityData] = useState<Record<string, number>>({});
  const [userAnomalies, setUserAnomalies] = useState<UserAnomalyRow[]>([]);
  const [userSummary, setUserSummary] = useState<UserBehaviorSummary | null>(null);
  const [malwareAlerts, setMalwareAlerts] = useState<MalwareAlert[]>([]);
  const [allMalwareScans, setAllMalwareScans] = useState<MalwareAlert[]>([]);
  const [malwareSummary, setMalwareSummary] = useState<MalwareSummary>({
    total_scanned: 0,
    malware_count: 0,
    benign_count: 0,
    unknown_count: 0,
    last_scan_ts: null,
  });
  const [sysmonAlerts, setSysmonAlerts] = useState<SysmonBehaviorAlert[]>([]);
  const [systemAnomalies, setSystemAnomalies] = useState<any[]>([]);
  const [sysmonLogs, setSysmonLogs] = useState<any[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointInfo[]>([]);
  const [endpointAlerts, setEndpointAlerts] = useState<EndpointAlert[]>([]);
  // Honeypot / deception hits (flattened, newest first, tagged with endpoint).
  const [honeypotHits, setHoneypotHits] = useState<HoneypotHit[]>([]);
  const [commandResults, setCommandResults] = useState<CommandResult[]>([]);
  const [activeEndpointId, setActiveEndpointId] = useState<string | null>(null);
  const [endpointFusionAlerts, setEndpointFusionAlerts] = useState<EndpointFusionAlert[]>([]);
  const [mongoOk, setMongoOk] = useState<boolean | undefined>(undefined);
  const [behavioralDetectorLoaded, setBehavioralDetectorLoaded] = useState<boolean | undefined>(undefined);
  const [fusionScore, setFusionScore] = useState<number | undefined>(undefined);
  const [socAlerts, setSocAlerts] = useState<SocAlert[]>([]);
  const [socketConnected, setSocketConnected] = useState(false);

  // ── Attack Graph alert count ──────────────────────────────────────────────────
  const [attackGraphAlertCount, setAttackGraphAlertCount] = useState(0);

  // ── Attack Reconstruction view state ─────────────────────────────────────────
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(null);

  const handleInvestigateIncident = useCallback((incidentId: string) => {
    setActiveIncidentId(incidentId);
    setActiveView("attack-reconstruction");
  }, []);

  // ── EDR Response Orchestration state ─────────────────────────────────────────
  const [responsePlans, setResponsePlans] = useState<ResponsePlan[]>([]);
  const [responseRequiredAlert, setResponseRequiredAlert] = useState<ResponsePlan | null>(null);
  const [incidentReports, setIncidentReports] = useState<IncidentReport[]>([]);

  // ── Alert Siren state ────────────────────────────────────────────────────────
  const [sirenActive, setSirenActive] = useState(false);
  const [sirenSeverity, setSirenSeverity] = useState<'HIGH' | 'CRITICAL'>('HIGH');
  const [sirenTimestamp, setSirenTimestamp] = useState<string | undefined>(undefined);

  // ── Siren audio controls ─────────────────────────────────────────────────────
  // audioEnabled starts false — the user must enable via Settings first.
  const { audioEnabled, enableAudio, disableAudio } = useSirenAudio();

  const handleEnableAudio = useCallback(() => {
    enableAudio();
  }, [enableAudio]);

  const handleDisableAudio = useCallback(() => {
    disableAudio();
  }, [disableAudio]);

  const socketRef = useRef<Socket | null>(null);

  // ── fetchEndpoints — lifted to component scope so the socket handler can call it ──
  const fetchEndpoints = useCallback(async () => {
    try {
      const res = await authAxios.get(`${BACKEND_URL}/endpoint/list`, { timeout: 5000 });
      const incoming: EndpointInfo[] = res.data?.endpoints ?? [];
      setEndpoints(prev => {
        // Merge API snapshot into current state so real-time socket data
        // (isolated status, blocked_ips, live CPU/memory) is not wiped.
        // Use a Map keyed by endpoint_id to guarantee uniqueness.
        const map = new Map<string, EndpointInfo>();
        // Seed with current live state so socket-enriched fields are preserved.
        for (const ep of prev) {
          if (ep.endpoint_id) map.set(ep.endpoint_id, ep);
        }
        // Overlay with authoritative registry data (API is source of truth for identity fields).
        for (const ep of incoming) {
          if (
            !ep.endpoint_id ||
            ep.endpoint_id === 'server_host' ||
            ep.endpoint_id.toLowerCase().startsWith('demo-') ||
            ep.hostname?.toUpperCase().startsWith('DEMO-')
          ) continue;
          const existing = map.get(ep.endpoint_id);
          map.set(ep.endpoint_id, existing ? { ...existing, ...ep } : ep);
        }
        return Array.from(map.values());
      });
    } catch {
      // Endpoint list unavailable — leave existing state intact
    }
  }, []);

  // ── Sync isMonitoring from backend /health on mount ─────────────────────────
  useEffect(() => {
    const syncMonitoringState = async () => {
      try {
        const res = await axios.get(`${BACKEND_URL}/health`, { timeout: 5000 });
        const running = res.data?.monitoring === true;
        setIsMonitoring(running);
        isMonitoringRef.current = running;
        if (running) {
          setStatus({ status: "started", message: "Monitoring active — network loop running" });
        }
        const bdLoaded = res.data?.system_model?.behavioral_detector_loaded;
        if (typeof bdLoaded === "boolean") {
          setBehavioralDetectorLoaded(bdLoaded);
        }
      } catch {
        // Backend not yet ready — leave isMonitoring=false
      }
    };

    syncMonitoringState();
    fetchEndpoints();

    // Poll every 60 s so the endpoint list stays fresh after backend restarts
    const intervalId = setInterval(() => {
      fetchEndpoints();
    }, 60_000);

    return () => clearInterval(intervalId);
  }, [fetchEndpoints]);

  // ── Fetch response plans + incident reports when authenticated ───────────────
  // Runs on mount and whenever auth state changes (e.g. after login / re-login).
  // This ensures reports and plans persist across page reloads and re-logins.
  useEffect(() => {
    if (!isAuthenticated) return;

    const fetchResponsePlans = async () => {
      try {
        const res = await authAxios.get(`${BACKEND_URL}/response/plans`, {
          timeout: 5000,
          params: { limit: 20 },
        });
        const plans: ResponsePlan[] = res.data?.plans ?? [];
        if (plans.length > 0) setResponsePlans(plans);
      } catch {
        // Plans unavailable on load — socket events will populate
      }
    };

    const fetchIncidentReports = async () => {
      try {
        const res = await authAxios.get(`${BACKEND_URL}/reports`, {
          timeout: 5000,
          params: { limit: 50 },
        });
        const reports: IncidentReport[] = res.data?.reports ?? [];
        // Always overwrite with the authoritative server list — do not
        // condition on length > 0, so that re-login always restores state.
        setIncidentReports(reports);
      } catch {
        // Reports unavailable on load — socket events will populate
      }
    };

    fetchResponsePlans();
    fetchIncidentReports();
  }, [isAuthenticated]);

  // ── MongoDB status poll (every 30 s) ─────────────────────────────────────────
  useEffect(() => {
    const fetchMongo = async () => {
      try {
        const res = await axios.get(`${BACKEND_URL}/storage-status`, { timeout: 8000 });
        setMongoOk(res.data?.mongo_ok === true);
      } catch {
        setMongoOk(false);
      }
    };
    fetchMongo();
    const interval = setInterval(fetchMongo, 30000);
    return () => clearInterval(interval);
  }, []);

  // ── Socket.IO (single connection owned here) ─────────────────────────────────
  useEffect(() => {
    const socket = io(BACKEND_URL, {
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 2000,
      auth: { token: localStorage.getItem('access_token') },
    });
    socketRef.current = socket;

    socket.on("connect", () => setSocketConnected(true));
    socket.on("disconnect", () => setSocketConnected(false));

    socket.on("network", (data: RawFlowPayload) => {
      const mapped = mapRawToFlow(data);

      setFlows((prev) => [mapped, ...prev].slice(0, MAX_TABLE_ROWS));

      setStats((prev) => ({
        total: prev.total + 1,
        attacks: prev.attacks + (mapped.prediction === "ATTACK" ? 1 : 0),
        normal: prev.normal + (mapped.prediction === "NORMAL" ? 1 : 0),
        cycles: data.cycle ?? prev.cycles,
      }));

      const t = new Date().toLocaleTimeString();
      setTimelineData((prev) => {
        const last = prev[prev.length - 1];
        if (last?.time === t) {
          return [
            ...prev.slice(0, -1),
            {
              ...last,
              attacks: last.attacks + (mapped.prediction === "ATTACK" ? 1 : 0),
              normal: last.normal + (mapped.prediction === "NORMAL" ? 1 : 0),
            },
          ];
        }
        return [
          ...prev,
          {
            time: t,
            attacks: mapped.prediction === "ATTACK" ? 1 : 0,
            normal: mapped.prediction === "NORMAL" ? 1 : 0,
          },
        ].slice(-MAX_CHART_POINTS);
      });

      setAttackTypeData((prev) => ({
        ...prev,
        [mapped.attack_type]: (prev[mapped.attack_type] ?? 0) + 1,
      }));

      setSeverityData((prev) => ({
        ...prev,
        [mapped.severity]: (prev[mapped.severity] ?? 0) + 1,
      }));
    });

    socket.on("monitoring_status", (data: StatusEvent) => {
      // Merge monitoring diagnostics into existing status — the event from the
      // backend never includes `status` or `message`, so a plain setStatus(data)
      // would wipe those fields and blank out the top-bar dot and label.
      setStatus(prev => ({
        ...prev,
        ...data,
        status:  "capturing",
        message: `Monitoring active — cycle ${data.cycle ?? prev.cycle ?? "?"}`,
      }));
      setIsMonitoring(true);
      isMonitoringRef.current = true;
      if (data.cycle != null) {
        setStats((prev) => ({ ...prev, cycles: data.cycle ?? prev.cycles }));
      }
    });

    socket.on("user_anomaly", (data: UserAnomalyRow) => {
      if (!isMonitoringRef.current) return;
      setUserAnomalies((prev) => {
        if (data.source === "endpoint" && data.endpoint_id) {
          // Deduplicate by endpoint_id only — user can be empty on 0-session cycles
          const idx = prev.findIndex(
            (r) => r.source === "endpoint" && r.endpoint_id === data.endpoint_id
          );
          // Map flags → shap_explanation so "Reasons" chips render
          const flags = (data as any).flags;
          const enriched: UserAnomalyRow = {
            ...data,
            shap_explanation: data.shap_explanation?.length
              ? data.shap_explanation
              : (Array.isArray(flags) ? flags : []),
          };
          if (idx >= 0) {
            const prev_row = prev[idx];
            // Preserve non-empty user/hostname when new cycle has empty values
            const merged: UserAnomalyRow = {
              ...prev_row,
              ...enriched,
              user: enriched.user || prev_row.user,
              current_user: enriched.current_user || prev_row.current_user,
              hostname: enriched.hostname || prev_row.hostname,
            };
            const updated = [...prev];
            updated[idx] = merged;
            return updated;
          }
          return [enriched, ...prev].slice(0, 50);
        }
        return [data, ...prev].slice(0, 50);
      });
    });

    socket.on("user_behavior_summary", (data: UserBehaviorSummary) => {
      if (!isMonitoringRef.current) return;
      setUserSummary(data);
      // Accumulate all users from every 300-second inference cycle so the
      // User Behavior LOG builds up a historical record over time.
      // Each cycle prepends its rows as new entries — the table shows the
      // rolling history (newest at top), not just the latest snapshot.
      // Endpoint-sourced rows are never replaced by Winlogbeat summary rows.
      if (data.users && data.users.length > 0) {
        setUserAnomalies((prev) => {
          // Prepend the new cycle's rows ahead of the existing list.
          // New entries always appear at the top regardless of label/score.
          const newRows = [...data.users!];
          const combined = [...newRows, ...prev];
          // Cap the rolling history at 200 entries (100 cycles × ~2 users each)
          // to prevent unbounded memory growth during long monitoring sessions.
          return combined.slice(0, 200);
        });
      }
    });

    socket.on("malware_alert", (data: MalwareAlert) => {
      setMalwareAlerts((prev) => [data, ...prev].slice(0, 50));
      const effLabel = data.label
        ?? (data.prediction === "MALWARE" ? "malicious"
          : data.prediction === "BENIGN" ? "benign"
          : data.prediction === "SUSPICIOUS" ? "suspicious"
          : "unknown");
      const isMalware = effLabel === "malicious" && !data.trusted;
      const isBenign  = effLabel === "benign";
      const isUnknown = effLabel === "unknown";
      setMalwareSummary((prev) => ({
        total_scanned: prev.total_scanned + 1,
        malware_count: prev.malware_count + (isMalware ? 1 : 0),
        benign_count: prev.benign_count + (isBenign ? 1 : 0),
        unknown_count: prev.unknown_count + (isUnknown ? 1 : 0),
        last_scan_ts: data.ts,
      }));
    });

    socket.on("malware_scan", (data: MalwareAlert) => {
      setAllMalwareScans((prev) => [data, ...prev].slice(0, 100));
      const effLabel = data.label
        ?? (data.prediction === "MALWARE" ? "malicious"
          : data.prediction === "BENIGN" ? "benign"
          : data.prediction === "SUSPICIOUS" ? "suspicious"
          : "unknown");
      if (effLabel !== "malicious") {
        setMalwareSummary((prev) => ({
          total_scanned: prev.total_scanned + 1,
          malware_count: prev.malware_count,
          benign_count: prev.benign_count + (effLabel === "benign" ? 1 : 0),
          unknown_count: prev.unknown_count + (effLabel === "unknown" ? 1 : 0),
          last_scan_ts: data.ts,
        }));
      }
    });

    socket.on("sysmon_behavior_alert", (data: SysmonBehaviorAlert) => {
      if (!isMonitoringRef.current) return;
      setSysmonAlerts((prev) => [data, ...prev].slice(0, 50));
    });

    socket.on("system_anomaly", (data: any) => {
      if (!isMonitoringRef.current) return;
      setSystemAnomalies(prev => [data, ...prev].slice(0, 50));
      // Keep gauge alive during system-only monitoring — seed fusionScore from
      // anomaly score so hasFusionData becomes true as soon as any data arrives.
      // fusion_alert will later override this with the authoritative fused value.
      if (typeof data.score === "number") {
        setFusionScore(prev => prev === undefined ? Math.round(data.score * 100) : prev);
      }
    });

    socket.on("sysmon_log", (data: any) => {
      if (!isMonitoringRef.current) return;
      setSysmonLogs(prev => [data, ...prev].slice(0, 200));
    });

    socket.on("fusion_alert", (data: FusionAlert) => {
      setFusionScore(Math.round(data.threat_score * 100));

      if (data.severity === 'HIGH' || data.severity === 'CRITICAL') {
        setSirenSeverity(data.severity as 'HIGH' | 'CRITICAL');
        setSirenTimestamp(new Date().toLocaleTimeString());
        setSirenActive(true);
      }
    });

    socket.on("soc_alert", (data: SocAlert) => {
      setSocAlerts(prev => [data, ...prev].slice(0, 50));

      if (data.final_severity === 'HIGH' || data.final_severity === 'CRITICAL') {
        setSirenSeverity(data.final_severity as 'HIGH' | 'CRITICAL');
        setSirenTimestamp(new Date().toLocaleTimeString());
        setSirenActive(true);
      }
    });

    socket.on("endpoint_update", (data: any) => {
      // Guard: skip server-host entries and any event with missing/invalid endpoint_id.
      // A missing endpoint_id would cause phantom cards because findIndex returns -1
      // and the entry gets appended as a new (fake) endpoint every time.
      const epId: string | undefined = (data as EndpointInfo).endpoint_id;
      const epHostname: string = (data as EndpointInfo).hostname ?? "";
      if (
        !epId || typeof epId !== 'string' || epId.trim() === '' ||
        epId === 'server_host' ||
        epId.toLowerCase().startsWith('demo-') ||
        epHostname.toUpperCase().startsWith('DEMO-')
      ) return;

      // Update endpoint card state
      setEndpoints(prev => {
        const idx = prev.findIndex(e => e.endpoint_id === epId);
        if (idx >= 0) {
          // Merge update but never overwrite good identity fields with empty strings
          const updated = [...prev];
          updated[idx] = {
            ...updated[idx],
            ...data,
            ip_address: (data as any).ip_address || updated[idx].ip_address,
            os:         (data as any).os         || updated[idx].os,
            username:   (data as any).username   || updated[idx].username,
            hostname:   (data as any).hostname   || updated[idx].hostname,
          };
          return updated;
        }
        // Only add NEW endpoints that have sent telemetry within the last 60 seconds.
        // Stale endpoint_update events (from SOAR ACKs on old entries) are ignored.
        const lastSeen = (data as EndpointInfo).last_seen;
        if (lastSeen) {
          try {
            const age = (Date.now() - new Date(lastSeen).getTime()) / 1000;
            if (age > 60) return prev; // stale — do not add to grid
          } catch {
            return prev; // unparseable timestamp — skip
          }
        }
        // Belt-and-suspenders: run a dedup pass on the entire array after adding
        // so that if two rapid socket events both saw an empty prev they can't
        // create two cards for the same endpoint_id.
        const next = [data as EndpointInfo, ...prev];
        const seen = new Set<string>();
        return next.filter(ep => {
          if (!ep.endpoint_id || seen.has(ep.endpoint_id)) return false;
          seen.add(ep.endpoint_id);
          return true;
        });
      });

      // Populate User Behavior panel from endpoint agent's user_behavior field.
      // The backend sets this on every /endpoint/ingest cycle when
      // UserBehaviorAgent.score_session_telemetry() runs.
      const ub = data.user_behavior as {
        score?: number;
        concurrent_sessions?: number;
        unusual_hour?: number;
        has_remote_session?: number;
        is_machine_account?: number;
        current_user?: string;
        flags?: string[];
        severity?: string;
      } | undefined;

      if (ub && data.endpoint_id) {
        const ubScore = ub.score ?? 0;
        const ubRow: UserAnomalyRow = {
          user: ub.current_user || data.hostname || data.endpoint_id,
          current_user: ub.current_user || data.hostname || data.endpoint_id,
          hostname: data.hostname || data.endpoint_id,
          endpoint_id: data.endpoint_id,
          source: "endpoint",
          anomaly_score: ubScore,
          user_score: ubScore,
          prediction_label: ubScore >= 0.5 ? "ANOMALY" : "NORMAL",
          concurrent_sessions: ub.concurrent_sessions ?? 0,
          unusual_hour: ub.unusual_hour ?? 0,
          has_remote_session: ub.has_remote_session ?? 0,
          is_machine_account: ub.is_machine_account ?? 0,
          shap_explanation: Array.isArray(ub.flags) ? ub.flags : [],
          fusion: ub.severity
            ? { severity: ub.severity }
            : undefined,
          ts: new Date().toISOString(),
        };

        setUserAnomalies(prev => {
          const existingIdx = prev.findIndex(
            r => r.source === "endpoint" && r.endpoint_id === ubRow.endpoint_id
          );
          if (existingIdx >= 0) {
            const existing = prev[existingIdx];
            const merged: UserAnomalyRow = {
              ...existing,
              ...ubRow,
              // Preserve better identity info from the existing row
              user: ubRow.user || existing.user,
              current_user: ubRow.current_user || existing.current_user,
              hostname: ubRow.hostname || existing.hostname,
              // Merge shap_explanation: prefer longer/more detailed list
              shap_explanation: (ubRow.shap_explanation?.length ?? 0) >= (existing.shap_explanation?.length ?? 0)
                ? ubRow.shap_explanation
                : existing.shap_explanation,
            };
            const updated = [...prev];
            updated[existingIdx] = merged;
            return updated;
          }
          return [ubRow, ...prev].slice(0, 200);
        });
      }
    });

    socket.on("endpoint_alert", (data: EndpointAlert) => {
      setEndpointAlerts(prev => [data, ...prev].slice(0, 50));
    });

    socket.on("honeypot_alert", (data: any) => {
      const rawHits: any[] = Array.isArray(data?.hits) ? data.hits : [];
      const tagged: HoneypotHit[] = rawHits.map(h => ({
        endpoint_id: data.endpoint_id,
        hostname: data.hostname,
        decoy_port: h.decoy_port,
        service: h.service,
        attacker_ip: h.attacker_ip,
        attacker_port: h.attacker_port,
        data_preview: h.data_preview,
        count: h.count,
        timestamp: h.timestamp,
        last_seen: h.last_seen,
      }));
      if (tagged.length) {
        setHoneypotHits(prev => [...tagged, ...prev].slice(0, 200));
        const ips = (data.attacker_ips ?? []).join(", ") || "unknown";
        toast.error(`🍯 Honeypot triggered on ${data.hostname ?? data.endpoint_id}: ${ips}`,
          { duration: 5000 });
      }
    });

    socket.on("endpoint_offline", (data: { endpoint_id: string; hostname?: string; reason?: string; timestamp?: string }) => {
      setEndpoints(prev =>
        prev.map(e =>
          e.endpoint_id === data.endpoint_id
            ? { ...e, status: 'offline' as const, last_seen: data.timestamp ?? e.last_seen }
            : e
        )
      );
    });

    socket.on("command_result", (data: CommandResult) => {
      setCommandResults(prev => [data, ...prev].slice(0, 20));

      // Human-readable action labels for toast
      const ACTION_LABELS: Record<string, string> = {
        block_ip:              "Block IP",
        unblock_ip:            "Unblock IP",
        isolate_host:          "Isolate Host",
        unisolate_host:        "Unisolate Host",
        kill_process:          "Kill Process",
        quarantine_file:       "Quarantine File",
        restore_quarantine_file: "Restore File",
        lock_account:          "Lock Account",
        unlock_account:        "Unlock Account",
        scan_filesystem:       "Scan Filesystem",
        monitor_persistence:   "Monitor Persistence",
      };

      const actionLabel = ACTION_LABELS[data.action ?? ""] ?? (data.action ?? "Command");
      const hostname = (() => {
        // We don't have direct access to endpoints here, so use endpoint_id as fallback
        return data.endpoint_id === "server_host" ? "Server" : data.endpoint_id;
      })();
      const resultMsg = data.result_message ?? data.message ?? "";
      const targetStr = data.target ? ` [${data.target}]` : "";
      const isCompleted = data.success || data.status === "completed";

      // ── Distinct, prominent alert for ACCOUNT LOCKOUTS (insider-threat response) ──
      if (data.action === "lock_account") {
        const advisory = /advisory/i.test(resultMsg);
        if (advisory) {
          // Server self-guard / unresolved target — safe skip, not a real lockout
          toast(`🛡️ Lock Account (advisory) — ${hostname}: ${resultMsg.slice(0, 100)}`, {
            id: `lock-${data.endpoint_id}-${data.target}`,
            duration: 8000,
            position: "top-center",
            style: {
              background: "var(--bg-sidebar)",
              color: "#f59e0b",
              border: "1px solid rgba(245,158,11,0.5)",
              borderRadius: 10,
              fontFamily: "'Fira Code', monospace",
              fontSize: 13,
              fontWeight: 700,
              padding: "12px 18px",
              boxShadow: "0 0 22px rgba(245,158,11,0.3)",
              maxWidth: 520,
            },
            icon: "ⓘ",
          });
          return;
        }
        if (isCompleted) {
          // Real lockout executed on an endpoint — headline SOC event
          toast(`🔒 USER SIGNED OUT — ${data.target ?? "account"} locked on ${hostname}`, {
            id: `lock-${data.endpoint_id}-${data.target}`,
            duration: 10000,
            position: "top-center",
            style: {
              background: "#b91c1c",
              color: "#ffffff",
              border: "2px solid #ff6b6b",
              borderRadius: 12,
              fontFamily: "'Fira Code', monospace",
              fontSize: 14,
              fontWeight: 800,
              letterSpacing: 0.4,
              padding: "16px 24px",
              boxShadow: "0 0 34px rgba(220,38,38,0.65)",
              maxWidth: 560,
            },
            icon: "🚫",
          });
          return;
        }
        // failed lockout falls through to the generic error toast below
      }

      if (isCompleted) {
        toast.success(`${actionLabel}${targetStr} completed on ${hostname}`, {
          duration: 6000,
          position: "bottom-right",
          style: {
            background: "var(--bg-sidebar)",
            color: "#00ff88",
            border: "1px solid rgba(0,255,136,0.45)",
            borderRadius: 10,
            fontFamily: "'Fira Code', monospace",
            fontSize: 12,
            fontWeight: 700,
            padding: "10px 16px",
            boxShadow: "0 0 18px rgba(0,255,136,0.25)",
          },
          icon: "✓",
        });
      } else {
        const failMsg = resultMsg ? `: ${resultMsg.slice(0, 80)}` : "";
        toast.error(`${actionLabel}${targetStr} FAILED on ${hostname}${failMsg}`, {
          duration: 8000,
          position: "bottom-right",
          style: {
            background: "var(--bg-sidebar)",
            color: "#ff3366",
            border: "1px solid rgba(255,51,102,0.45)",
            borderRadius: 10,
            fontFamily: "'Fira Code', monospace",
            fontSize: 12,
            fontWeight: 700,
            padding: "10px 16px",
            boxShadow: "0 0 18px rgba(255,51,102,0.25)",
          },
          icon: "✗",
        });
      }
    });

    socket.on("command_queued", (data: { endpoint_id: string; action: string; target?: string; status?: string }) => {
      const endpointLabel = data.endpoint_id ?? "unknown";
      toast(`SOAR command queued: ${data.action} → ${endpointLabel}`, {
        duration: 4000,
        position: "bottom-right",
        style: {
          background: "var(--bg-card)",
          color: "var(--accent-cyan)",
          border: "1px solid rgba(47,224,224,0.35)",
          borderRadius: 10,
          fontFamily: "'Fira Code', monospace",
          fontSize: 12,
          fontWeight: 700,
          padding: "10px 16px",
          boxShadow: "0 0 14px rgba(0,212,255,0.2)",
        },
        icon: "⚡",
      });
    });

    socket.on("endpoint_command_status", (data: CommandResult) => {
      setCommandResults(prev => [data, ...prev].slice(0, 50));
    });

    socket.on("endpoint_fusion_alert", (data: EndpointFusionAlert) => {
      setEndpointFusionAlerts(prev => [data, ...prev].slice(0, 200));
    });

    socket.on("network_anomaly", (data: any) => {
      // Keep gauge alive during network-only monitoring — seed fusionScore from
      // confidence so hasFusionData becomes true as soon as attacks are detected.
      // fusion_alert will later override this with the authoritative fused value.
      if (typeof data.confidence === "number" && data.confidence > 0) {
        setFusionScore(prev => prev === undefined ? data.confidence : prev);
      }

      const flow: FlowResult = {
        cycle: 0,
        timestamp: data.ts ?? new Date().toISOString(),
        src_ip: data.src_ip ?? data.hostname ?? data.endpoint_id ?? "endpoint",
        dest_ip: "",
        src_port: 0,
        dest_port: 0,
        protocol: "TCP",
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
        flow_duration: 0,
        flow_bytes_per_s: 0,
        prediction: "ATTACK",
        attack_type: data.attack_type ?? "Unknown",
        confidence: typeof data.confidence === "number" ? data.confidence : 0,
        severity: (data.severity as FlowResult["severity"]) ?? "MEDIUM",
        color: "#ff3366",
        icon: "⚠",
        description: `Endpoint network attack: ${data.attack_type ?? "Unknown"}`,
        top3: [],
        traffic_label: data.attack_type ?? "ATTACK",
        traffic_icon: "⚠",
        traffic_description: `Detected on endpoint ${data.hostname ?? data.endpoint_id}`,
        traffic_category: "ATTACK",
      };
      setFlows(prev => [flow, ...prev].slice(0, MAX_TABLE_ROWS));
      setStats(prev => ({
        ...prev,
        total: prev.total + 1,
        attacks: prev.attacks + 1,
      }));
      setAttackTypeData(prev => ({
        ...prev,
        [flow.attack_type]: (prev[flow.attack_type] ?? 0) + 1,
      }));
      setSeverityData(prev => ({
        ...prev,
        [flow.severity]: (prev[flow.severity] ?? 0) + 1,
      }));
    });

    socket.on("cleanup_complete", () => {
      fetchEndpoints();
    });

    // ── EDR Response Orchestration events ──────────────────────────────────────
    socket.on("response_required", (plan: ResponsePlan) => {
      setResponsePlans(prev => [plan, ...prev.slice(0, 49)]);
      setResponseRequiredAlert(plan);
    });

    socket.on("response_plan_ready", (plan: ResponsePlan) => {
      setResponsePlans(prev => [plan, ...prev.slice(0, 49)]);
    });

    socket.on("auto_response_completed", (data: any) => {
      const sev = data.severity ?? "HIGH";
      const attack = data.attack_type ?? "Threat";
      const endpoint = data.endpoint_id ?? "unknown";
      const actions: string[] = data.actions_taken ?? [];

      // Show prominent toast notification
      toast.success(
        `Auto-Response Executed\n${attack} on ${endpoint}\nActions: ${actions.slice(0, 3).join(", ")}${actions.length > 3 ? "..." : ""}`,
        { duration: 8000, position: "bottom-right", style: { background: sev === "CRITICAL" ? "#7f1d1d" : "#1c1917", color: "#fff", border: "1px solid #ef4444", maxWidth: 420 } }
      );

      // If a report was auto-generated, download it with auth headers
      if (data.report?.incident_id) {
        const incidentId = data.report.incident_id;
        authAxios
          .get(`${BACKEND_URL}/reports/${incidentId}/download`, { responseType: "blob" })
          .then((res) => {
            const blob = new Blob([res.data], { type: "application/pdf" });
            const blobUrl = URL.createObjectURL(blob);
            const anchor = document.createElement("a");
            anchor.href = blobUrl;
            anchor.download = `incident_${incidentId}.pdf`;
            anchor.click();
            setTimeout(() => URL.revokeObjectURL(blobUrl), 5000);
            toast(`Incident report auto-downloaded: ${incidentId}`, {
              duration: 6000,
              position: "bottom-right",
              style: { background: "var(--bg-secondary)", color: "var(--text-secondary)", border: "1px solid var(--border-color)" },
            });
          })
          .catch(() => {
            toast.error("Auto-response report download failed — check PDF in Endpoints view.", { duration: 5000, position: "bottom-right" });
          });
      }

      // Refresh response plans state
      setResponsePlans(prev => prev.map(p =>
        p.plan_id === data.plan_id ? { ...p, status: "executed" as const } : p
      ));
    });

    socket.on("response_executed", (data: { plan_id: string; command_ids?: string[] }) => {
      // Optimistic local update
      setResponsePlans(prev =>
        prev.map(p => p.plan_id === data.plan_id ? { ...p, status: "executed" as const } : p)
      );
      setResponseRequiredAlert(prev =>
        prev?.plan_id === data.plan_id ? null : prev
      );
      // Re-fetch authoritative plan list from the server to get updated statuses
      authAxios.get(`${BACKEND_URL}/response/plans`, {
        timeout: 5000,
        params: { limit: 20 },
      }).then((res) => {
        const plans: ResponsePlan[] = res.data?.plans ?? [];
        if (plans.length > 0) setResponsePlans(plans);
      }).catch(() => {
        // Keep the optimistic local update on failure
      });
    });

    socket.on("report_generated", (report: IncidentReport) => {
      // Prepend the new report immediately for instant UI feedback
      setIncidentReports(prev => [report, ...prev.slice(0, 49)]);
      // Then re-fetch the full list to ensure consistency
      authAxios.get(`${BACKEND_URL}/reports`, {
        timeout: 5000,
        params: { limit: 50 },
      }).then((res) => {
        const reports: IncidentReport[] = res.data?.reports ?? [];
        if (reports.length > 0) setIncidentReports(reports);
      }).catch(() => {
        // Keep the socket-delivered report on failure
      });
    });

    return () => {
      socket.off("connect");
      socket.off("disconnect");
      socket.off("network");
      socket.off("monitoring_status");
      socket.off("user_anomaly");
      socket.off("user_behavior_summary");
      socket.off("malware_alert");
      socket.off("malware_scan");
      socket.off("sysmon_behavior_alert");
      socket.off("system_anomaly");
      socket.off("sysmon_log");
      socket.off("fusion_alert");
      socket.off("soc_alert");
      socket.off("endpoint_update");
      socket.off("endpoint_alert");
      socket.off("honeypot_alert");
      socket.off("endpoint_offline");
      socket.off("command_result");
      socket.off("command_queued");
      socket.off("endpoint_command_status");
      socket.off("endpoint_fusion_alert");
      socket.off("network_anomaly");
      socket.off("cleanup_complete");
      socket.off("response_required");
      socket.off("response_plan_ready");
      socket.off("response_executed");
      socket.off("report_generated");
      socket.off("auto_response_completed");
      socket.disconnect();
      socketRef.current = null;
    };
  }, [fetchEndpoints]);

  // ── Handlers ─────────────────────────────────────────────────────────────────
  const handleStart = useCallback(async () => {
    setLoading(true);
    try {
      await axios.get(`${BACKEND_URL}/start-monitoring`);
      setIsMonitoring(true);
      setFlows([]);
      setStats({ total: 0, attacks: 0, normal: 0, cycles: 0 });
      setTimelineData([]);
      setAttackTypeData({});
      setSeverityData({});
      setStatus({ status: "started", message: "Monitoring started — first capture in progress..." });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      setStatus({ status: "error", message: `Failed to start: ${msg}` });
    } finally {
      setLoading(false);
    }
  }, []);

  const handleStop = useCallback(async () => {
    setLoading(true);
    try {
      await axios.get(`${BACKEND_URL}/stop-monitoring`);
      setStatus({ status: "stopped", message: "Monitoring stopped." });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Unknown error";
      setStatus({ status: "error", message: `Failed to stop: ${msg}` });
    } finally {
      setIsMonitoring(false);
      isMonitoringRef.current = false;
      setLoading(false);
    }
  }, []);

  const handleLogout = useCallback(async () => {
    try {
      await logout();
    } catch {
      // Backend may be offline — tokens were cleared; proceed to login
    }
    navigate('/login');
  }, [logout, navigate]);

  const handleSendCommand = useCallback(async (cmd: EndpointCommand) => {
    try {
      await authAxios.post(`${BACKEND_URL}/endpoint/command`, cmd);
    } catch (err: any) {
      if (process.env.NODE_ENV === 'development') {
        console.error('[SOAR] Command send failed:', err?.response?.status, err?.message);
      }
    }
  }, []);

  // ── Status colour ─────────────────────────────────────────────────────────────
  const STATUS_COLOUR: Record<string, string> = {
    idle:       "#6b7280",
    started:    "#3b82f6",
    capturing:  "#8b5cf6",
    analyzing:  "#f59e0b",
    predicting: "#06b6d4",
    complete:   "#22c55e",
    stopped:    "#6b7280",
    error:      "#ef4444",
    no_data:    "#f59e0b",
  };
  const dotColour = STATUS_COLOUR[status.status] ?? "#6b7280";

  // ── Badge counts for sidebar ──────────────────────────────────────────────────
  const attackCount = stats.attacks;
  const anomalyCount = userAnomalies.filter((r) => r.prediction_label === "ANOMALY").length;
  const malwareCount = malwareSummary.malware_count;
  const sysmonCount = sysmonAlerts.filter(
    (a) => a.severity === "HIGH" || a.severity === "CRITICAL"
  ).length;

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div
      style={{
        display: "flex",
        minHeight: "100vh",
        background: "var(--bg-primary, #0a1120)",
        fontFamily: "'Inter', 'Segoe UI', system-ui, sans-serif",
        color: "var(--text-primary, #f1f5f9)",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Toast notifications rendered by the global <Toaster> in App.tsx */}

      {/* Alert Siren overlay */}
      <AlertSiren
        isActive={sirenActive}
        severity={sirenSeverity}
        timestamp={sirenTimestamp}
        onAcknowledge={() => setSirenActive(false)}
        audioEnabled={audioEnabled}
        onEnableAudio={handleEnableAudio}
      />

      {/* Subtle animated background grid */}
      <div
        style={{
          position: "fixed",
          inset: 0,
          backgroundImage: `
            linear-gradient(rgba(59,130,246,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(59,130,246,0.03) 1px, transparent 1px)
          `,
          backgroundSize: "40px 40px",
          pointerEvents: "none",
          zIndex: 0,
        }}
      />

      {/* Sidebar */}
      <Sidebar
        activeView={
          // Map extended views that aren't in ViewId to "overview" for highlight purposes
          (["settings", "about", "profile", "audit"].includes(activeView)
            ? (activeView as ViewId)
            : activeView) as ViewId
        }
        onNavigate={(v) => {
          setActiveView(v as ExtViewId);
          setActiveEndpointId(null);
          if (v === "endpoints") setResponseRequiredAlert(null);
        }}
        isMonitoring={isMonitoring}
        attackCount={attackCount}
        anomalyCount={anomalyCount}
        malwareCount={malwareCount}
        sysmonCount={sysmonCount}
        endpointOnlineCount={endpoints.filter(e => e.status === 'online').length}
        responseRequiredCount={responseRequiredAlert ? 1 : 0}
        attackGraphAlertCount={attackGraphAlertCount}
        userRole={user?.role}
        username={user?.username}
        onLogout={handleLogout}
      />

      {/* Main content */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, position: "relative", zIndex: 1 }}>
        {/* Top bar — stripped to: status dot, Audit Log, Start/Stop */}
        <div
          style={{
            height: 56,
            background: "var(--bg-sidebar, #0d1629)",
            borderBottom: "1px solid var(--border-color, #1e293b)",
            display: "flex",
            alignItems: "center",
            padding: "0 24px",
            gap: 12,
            flexShrink: 0,
          }}
        >
          {/* Status dot + message */}
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 7,
              fontSize: 12,
              color: isMonitoring ? "var(--text-muted)" : "var(--accent-amber)",
            }}
          >
            <span
              style={{
                display: "inline-block",
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: dotColour,
                boxShadow: isMonitoring ? `0 0 7px ${dotColour}` : "none",
                animation: isMonitoring ? "xdr-pulse 1.4s ease-in-out infinite" : "none",
              }}
            />
            {status.message}
          </span>

          {/* WebSocket connection status dot */}
          <motion.div
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              backgroundColor: socketConnected ? "#22c55e" : "#ef4444",
              display: "inline-block",
              marginLeft: 4,
              flexShrink: 0,
              cursor: "default",
            }}
            animate={{
              scale: socketConnected ? [1, 1.3, 1] : 1,
              boxShadow: socketConnected
                ? [
                    "0 0 0 0 rgba(34,197,94,0.4)",
                    "0 0 0 6px rgba(34,197,94,0)",
                    "0 0 0 0 rgba(34,197,94,0)",
                  ]
                : "none",
            }}
            transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
            title={socketConnected ? "Socket.IO connected" : "Socket.IO disconnected"}
          />

          <div style={{ flex: 1 }} />

          {/* Start / Stop Monitoring buttons */}
          <button
            onClick={handleStart}
            disabled={isMonitoring || loading}
            style={{
              padding: "7px 20px",
              borderRadius: 8,
              border: "none",
              background: isMonitoring || loading ? "var(--bg-surface)" : "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)",
              color: isMonitoring || loading ? "var(--text-muted)" : "#fff",
              fontWeight: 700,
              fontSize: 12,
              cursor: isMonitoring || loading ? "not-allowed" : "pointer",
              transition: "all 0.15s",
              letterSpacing: 0.5,
            }}
          >
            {loading && !isMonitoring ? "Starting..." : "Start Monitoring"}
          </button>
          <button
            onClick={handleStop}
            disabled={!isMonitoring || loading}
            style={{
              padding: "7px 20px",
              borderRadius: 8,
              border: "none",
              background: !isMonitoring || loading ? "var(--bg-surface)" : "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)",
              color: !isMonitoring || loading ? "var(--text-muted)" : "#fff",
              fontWeight: 700,
              fontSize: 12,
              cursor: !isMonitoring || loading ? "not-allowed" : "pointer",
              transition: "all 0.15s",
              letterSpacing: 0.5,
            }}
          >
            {loading && isMonitoring ? "Stopping..." : "Stop Monitoring"}
          </button>
        </div>

        {/* Scrollable view area */}
        <div style={{ flex: 1, overflowY: "auto", overflowX: "hidden" }}>
          <AnimatePresence mode="wait">
            {activeView === "audit" ? (
              <motion.div
                key="audit"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.18 }}
                style={{ padding: 24, height: "100%" }}
              >
                <div style={{ marginBottom: 16 }}>
                  <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: "var(--text-heading)", letterSpacing: -0.5 }}>
                    Audit Log
                  </h2>
                  <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
                    Real-time authentication and authorization event stream
                  </p>
                </div>
                {/* Audit Log: admin sees full event stream with shared socket; analysts/viewers are redirected */}
                {user?.role === "admin" ? (
                  <AuditLogPanel socket={socketRef.current ?? undefined} />
                ) : (
                  <div
                    style={{
                      padding: "32px 24px",
                      background: "var(--bg-card)",
                      borderLeft: "4px solid var(--accent-red)",
                      borderRadius: 12,
                      textAlign: "center",
                      maxWidth: 480,
                      margin: "0 auto",
                    }}
                  >
                    <span style={{ fontSize: 32, display: "block", marginBottom: 12 }}>🔒</span>
                    <div style={{ color: "var(--accent-red)", fontWeight: 800, fontSize: 14, letterSpacing: 1, marginBottom: 8 }}>
                      ACCESS RESTRICTED
                    </div>
                    <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>
                      Audit logs are available to admin role only.
                    </div>
                  </div>
                )}
              </motion.div>
            ) : activeView === "about" ? (
              <motion.div key="about" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }} style={{ height: "100%" }}>
                <AboutView />
              </motion.div>
            ) : activeView === "settings" ? (
              <motion.div key="settings" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <SettingsView audioEnabled={audioEnabled} onEnableAudio={handleEnableAudio} onDisableAudio={handleDisableAudio} />
              </motion.div>
            ) : activeView === "profile" ? (
              <motion.div key="profile" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <ProfileView endpoints={endpoints} />
              </motion.div>
            ) : activeView === "overview" ? (
              <motion.div key="overview" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <OverviewView
                  flows={flows}
                  stats={stats}
                  isMonitoring={isMonitoring}
                  userAnomalies={userAnomalies}
                  userSummary={userSummary}
                  timelineData={timelineData}
                  attackTypeData={attackTypeData}
                  malwareSummary={malwareSummary}
                  mongoOk={mongoOk}
                  fusionScore={fusionScore}
                  socAlerts={socAlerts}
                  socketConnected={socketConnected}
                  hasFusionData={fusionScore !== undefined}
                  activeThreatCount={
                    (flows ?? []).filter((f) => f.prediction === 'ATTACK').length +
                    (userAnomalies ?? []).length +
                    (malwareAlerts ?? []).filter((m) => m.label === 'malicious').length
                  }
                  endpoints={endpoints}
                  systemAnomalies={systemAnomalies}
                  endpointAlerts={endpointAlerts}
                  userRole={user?.role}
                  socket={socketRef.current}
                />
              </motion.div>
            ) : activeView === "network" ? (
              <motion.div key="network" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <NetworkView
                  flows={flows}
                  stats={stats}
                  isMonitoring={isMonitoring}
                  timelineData={timelineData}
                  attackTypeData={attackTypeData}
                  severityData={severityData}
                  monitoringCycle={status.cycle}
                  zeroFlowCycles={status.zero_flow_cycles}
                  suricataEveExists={status.suricata_eve_exists}
                  suricataEveBytes={status.suricata_eve_bytes}
                />
              </motion.div>
            ) : activeView === "attackgraph" ? (
              <motion.div
                key="attackgraph"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.18 }}
                style={{ height: "calc(100vh - 56px)" }}
              >
                <AttackGraphView onAlertCountChange={setAttackGraphAlertCount} />
              </motion.div>
            ) : activeView === "userbehavior" ? (
              <motion.div key="userbehavior" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <UserBehaviorView userAnomalies={userAnomalies} userSummary={userSummary} isMonitoring={isMonitoring} />
              </motion.div>
            ) : activeView === "alerts" ? (
              <motion.div key="alerts" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <AlertsView
                  flows={flows}
                  userAnomalies={userAnomalies}
                  malwareAlerts={malwareAlerts}
                  socAlerts={socAlerts}
                  responsePlans={responsePlans}
                  userRole={user?.role}
                />
              </motion.div>
            ) : activeView === "systemstatus" ? (
              <motion.div key="systemstatus" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <SystemStatusView isMonitoring={isMonitoring} />
              </motion.div>
            ) : activeView === "malware" ? (
              <motion.div key="malware" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <MalwareView alerts={malwareAlerts} allScans={allMalwareScans} summary={malwareSummary} />
              </motion.div>
            ) : activeView === "sysmon" ? (
              <motion.div key="sysmon" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <SysmonBehaviorView isMonitoring={isMonitoring} alerts={sysmonAlerts} sysmonLogs={sysmonLogs} systemAnomalies={systemAnomalies} userRole={user?.role} behavioralDetectorLoaded={behavioralDetectorLoaded} />
              </motion.div>
            ) : activeView === "endpoints" && activeEndpointId !== null ? (
              <motion.div key={`endpoint-detail-${activeEndpointId}`} initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <EndpointDetailView
                  endpointId={activeEndpointId}
                  endpointInfo={endpoints.find(e => e.endpoint_id === activeEndpointId)}
                  endpointAlerts={endpointAlerts}
                  fusionAlerts={endpointFusionAlerts}
                  onBack={() => setActiveEndpointId(null)}
                  onSendCommand={handleSendCommand}
                  commandResults={commandResults}
                />
              </motion.div>
            ) : activeView === "endpoints" ? (
              <motion.div key="endpoints" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.18 }}>
                <EndpointView
                  endpoints={endpoints}
                  endpointAlerts={endpointAlerts}
                  onSendCommand={handleSendCommand}
                  commandResults={commandResults}
                  onSelectEndpoint={setActiveEndpointId}
                  responsePlans={responsePlans}
                  incidentReports={incidentReports}
                  userRole={user?.role}
                  onInvestigateIncident={handleInvestigateIncident}
                  honeypotHits={honeypotHits}
                />
              </motion.div>
            ) : activeView === "attack-reconstruction" && activeIncidentId ? (
              <motion.div
                key={`reconstruction-${activeIncidentId}`}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.18 }}
                style={{ height: "calc(100vh - 56px)" }}
              >
                <AttackReconstructionView
                  incidentId={activeIncidentId}
                  onBack={() => {
                    setActiveView("endpoints");
                    setActiveIncidentId(null);
                  }}
                />
              </motion.div>
            ) : null}
          </AnimatePresence>
        </div>
      </div>

      {/* Global styles */}
      <style>{`
        * { box-sizing: border-box; }
        body { margin: 0; background: var(--bg-primary, #070A0F); }
        .App { text-align: left !important; }

        @keyframes xdr-pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50%       { opacity: 0.4; transform: scale(0.85); }
        }

        @keyframes xdr-glow {
          0%, 100% { box-shadow: 0 0 8px currentColor; }
          50%       { box-shadow: 0 0 20px currentColor; }
        }

        @keyframes xdr-spin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }

        @keyframes isolated-card-glow {
          0%, 100% { box-shadow: 0 0 20px rgba(255,80,0,0.8), 0 0 40px rgba(255,80,0,0.3); }
          50%       { box-shadow: 0 0 30px rgba(255,80,0,1), 0 0 60px rgba(255,80,0,0.5); }
        }

        @keyframes isolated-badge-blink {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.55; }
        }

        button:hover:not(:disabled) {
          filter: brightness(1.12);
          transition: filter 0.15s ease;
        }
      `}</style>
    </div>
  );
}
