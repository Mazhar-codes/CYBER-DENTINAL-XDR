// responseTypes.ts
// EDR Response Orchestration types — ResponsePlan, IncidentReport, ResponseAction

export interface ResponseAction {
  action: string;    // "kill_process" | "block_ip" | "isolate_host" | "scan_filesystem" | etc
  target?: string;
  reason?: string;
}

export interface ResponsePlan {
  plan_id: string;
  endpoint_id: string;
  severity: string;
  risk_level: string;
  summary: string;
  mitre_technique: string;
  recommended_actions: ResponseAction[];
  auto_execute: boolean;
  created_at: string;
  attack_type?: string;
  shap_explanation?: Array<{ feature: string; shap_value: number; importance?: number }>;
  /** Lifecycle status — set client-side when response_executed event arrives */
  status?: "open" | "executing" | "contained" | "partial" | "failed" | "executed" | "dismissed";
}

export interface IncidentReport {
  incident_id: string;
  plan_id: string;
  endpoint_id: string;
  severity: string;
  attack_type: string;
  pdf_path: string;
  generated_by: string;
  generated_at: string;
  status: string;
  download_url?: string;
}
