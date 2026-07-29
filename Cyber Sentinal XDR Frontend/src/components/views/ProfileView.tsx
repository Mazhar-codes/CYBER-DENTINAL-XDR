// ProfileView.tsx
// User profile — role-based sections: profile card (all), user management (admin), case notes (analyst).

import React, { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { authAxios } from "../../services/authService";
import { useAuth } from "../../context/AuthContext";
import { EndpointInfo } from "../shared/types";
import MFARecoveryPanel from "./ProfileView/MFARecoveryPanel";
import { ConfirmDialog } from "../shared/ConfirmDialog";
import { BACKEND_URL } from "../../config";
import DualOrbitLoader from "../shared/DualOrbitLoader";

const SECTION_LABEL: React.CSSProperties = {
  fontFamily: "'Fira Code', monospace",
  fontSize: 9,
  fontWeight: 700,
  letterSpacing: 1.8,
  textTransform: "uppercase",
  color: "var(--text-secondary)",
  marginBottom: 14,
  display: "block",
};

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

const ROLE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  admin:   { bg: "rgba(255,0,68,0.12)",   text: "#ff6688", border: "rgba(255,0,68,0.3)" },
  analyst: { bg: "var(--border-color)",   text: "var(--accent-cyan)", border: "rgba(47,224,224,0.30)" },
  viewer:  { bg: "rgba(0,255,136,0.08)",  text: "#00ff88", border: "rgba(0,255,136,0.25)" },
};

const ROLE_DESC: Record<string, string> = {
  admin:   "Full system access — monitoring, response, user management, settings, reports.",
  analyst: "Can investigate alerts, execute SOAR responses, generate reports. Cannot manage users.",
  viewer:  "Read-only access — view dashboards and alerts only. No execute permissions.",
};

// ── Neon pill button (for filter bar) ────────────────────────────────────────
function FilterPill({ label, active, accent, onClick }: { label: string; active: boolean; accent: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "3px 11px",
        borderRadius: 20,
        border: active ? `1px solid ${accent}` : "1px solid var(--border-color)",
        cursor: "pointer",
        background: active ? `${accent}1a` : "var(--bg-primary)",
        color: active ? accent : "var(--text-secondary)",
        fontWeight: active ? 700 : 400,
        fontSize: 11,
        transition: "all 0.15s",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </button>
  );
}

// ── Admin: User Management table ──────────────────────────────────────────────
interface AdminUser {
  id: string;
  username: string;
  email: string;
  role: string;
  two_factor_enabled: boolean;
  last_login: string | null;
  is_locked?: boolean;
}

function UserManagementPanel() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [createForm, setCreateForm] = useState(false);
  const [newUser, setNewUser] = useState({ username: "", email: "", password: "", role: "viewer" });

  // ── Filter state ─────────────────────────────────────────────────────────────
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState<"ALL" | "admin" | "analyst" | "viewer">("ALL");
  const [mfaFilter, setMfaFilter] = useState<"ALL" | "enabled" | "disabled">("ALL");
  const [statusFilter, setStatusFilter] = useState<"ALL" | "active" | "locked">("ALL");

  // ── Unified confirm dialog state ─────────────────────────────────────────────
  const [confirmDialog, setConfirmDialog] = useState<{
    open: boolean;
    title: string;
    message: string;
    variant: "danger" | "warning" | "info";
    confirmLabel: string;
    onConfirm: () => void;
  } | null>(null);

  const openConfirm = (cfg: Omit<NonNullable<typeof confirmDialog>, "open">) => {
    setConfirmDialog({ ...cfg, open: true });
  };
  const closeConfirm = () => setConfirmDialog(null);

  // ── Bug 1 fix: normalize user_id → id ────────────────────────────────────────
  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await authAxios.get(`${BACKEND_URL}/users`);
      const raw: any[] = res.data?.users ?? res.data ?? [];
      setUsers(
        raw.map((u: any) => ({
          id: u.user_id ?? u.id ?? u._id?.toString() ?? "",
          username: u.username,
          email: u.email,
          role: u.role,
          two_factor_enabled: u.two_factor_enabled ?? false,
          last_login: u.last_login ?? null,
        }))
      );
    } catch {
      setMsg("Failed to load users — check admin permissions.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const showMsg = (text: string) => {
    setMsg(text);
    setTimeout(() => setMsg(null), 3500);
  };

  const handleCreateUser = async () => {
    if (!newUser.username.trim() || !newUser.email.trim() || !newUser.password.trim()) {
      showMsg("All fields are required.");
      return;
    }
    if (newUser.password.length < 8) {
      showMsg("Password must be at least 8 characters.");
      return;
    }
    try {
      await authAxios.post(`${BACKEND_URL}/users/create`, newUser);
      showMsg(`User "${newUser.username}" created successfully.`);
      setNewUser({ username: "", email: "", password: "", role: "viewer" });
      setCreateForm(false);
      fetchUsers();
    } catch (err: unknown) {
      const detail =
        (err as any)?.response?.data?.detail ??
        (err as any)?.response?.data?.message ??
        "Failed to create user.";
      showMsg(typeof detail === "string" ? detail : "Failed to create user.");
    }
  };

  // ── Bug 2 fix: POST not PATCH ─────────────────────────────────────────────────
  const handleChangeRole = async (userId: string, newRole: string) => {
    try {
      await authAxios.post(`${BACKEND_URL}/users/${userId}/role`, { role: newRole });
      showMsg("Role updated.");
      fetchUsers();
    } catch {
      showMsg("Failed to update role.");
    }
  };

  // ── Uses ConfirmDialog, Bug 1 fix: id normalised from fetchUsers ──────────────
  const handleDelete = (userId: string, username: string) => {
    openConfirm({
      title: "Delete User",
      message: `Permanently delete "${username}"? This cannot be undone. All sessions will be revoked.`,
      variant: "danger",
      confirmLabel: "Delete",
      onConfirm: async () => {
        closeConfirm();
        try {
          await authAxios.delete(`${BACKEND_URL}/users/${userId}`);
          showMsg(`User "${username}" deleted.`);
          fetchUsers();
        } catch {
          showMsg("Failed to delete user.");
        }
      },
    });
  };

  // ── Bug 3 fix: /force-logout not /logout ──────────────────────────────────────
  const handleForceLogout = (userId: string, username: string) => {
    openConfirm({
      title: "Force Logout",
      message: `Terminate all active sessions for "${username}"? They will need to log in again.`,
      variant: "warning",
      confirmLabel: "Force Logout",
      onConfirm: async () => {
        closeConfirm();
        try {
          await authAxios.post(`${BACKEND_URL}/users/${userId}/force-logout`);
          showMsg(`Sessions for "${username}" terminated.`);
        } catch {
          showMsg("Failed to force logout.");
        }
      },
    });
  };

  // Filtered users (client-side)
  const filteredUsers = React.useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    return users.filter((u) => {
      if (roleFilter !== "ALL" && u.role !== roleFilter) return false;
      if (mfaFilter === "enabled" && !u.two_factor_enabled) return false;
      if (mfaFilter === "disabled" && u.two_factor_enabled) return false;
      if (statusFilter === "locked" && !u.is_locked) return false;
      if (statusFilter === "active" && u.is_locked) return false;
      if (q) {
        const s = [u.username, u.email].join(" ").toLowerCase();
        if (!s.includes(q)) return false;
      }
      return true;
    });
  }, [users, searchQuery, roleFilter, mfaFilter, statusFilter]);

  const clearFilters = React.useCallback(() => {
    setSearchQuery(""); setRoleFilter("ALL"); setMfaFilter("ALL"); setStatusFilter("ALL");
  }, []);

  return (
    <Panel accent="#ff6688">
      <span style={SECTION_LABEL}>User Management</span>

      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 14, gap: 8 }}>
        <button
          onClick={fetchUsers}
          style={{
            padding: "6px 14px",
            borderRadius: 8,
            border: "1px solid var(--border-color)",
            background: "var(--bg-primary)",
            color: "var(--text-muted)",
            fontSize: 11,
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          Refresh
        </button>
        <button
          onClick={() => setCreateForm((v) => !v)}
          style={{
            padding: "6px 14px",
            borderRadius: 8,
            border: "1px solid rgba(255,102,136,0.3)",
            background: "rgba(255,102,136,0.08)",
            color: "#ff6688",
            fontSize: 11,
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          {createForm ? "Cancel" : "+ Create User"}
        </button>
      </div>

      {createForm && (
        <div
          style={{
            background: "var(--bg-primary)",
            border: "1px solid var(--border-color)",
            borderRadius: 10,
            padding: 16,
            marginBottom: 16,
            display: "flex",
            flexDirection: "column",
            gap: 10,
          }}
        >
          <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
            {[
              { label: "Username", key: "username", type: "text" },
              { label: "Email", key: "email", type: "email" },
              { label: "Password", key: "password", type: "password" },
            ].map(({ label, key, type }) => (
              <div key={key} style={{ flex: "1 1 180px" }}>
                <label style={{ fontSize: 10, color: "var(--text-secondary)", display: "block", marginBottom: 4 }}>
                  {label}
                </label>
                <input
                  type={type}
                  value={(newUser as any)[key]}
                  onChange={(e) =>
                    setNewUser((u) => ({ ...u, [key]: e.target.value }))
                  }
                  style={{
                    width: "100%",
                    padding: "8px 12px",
                    borderRadius: 8,
                    border: "1px solid var(--border-color)",
                    background: "var(--bg-primary)",
                    color: "var(--text-primary)",
                    fontSize: 12,
                    boxSizing: "border-box",
                    outline: "none",
                  }}
                />
              </div>
            ))}
            <div style={{ flex: "1 1 140px" }}>
              <label style={{ fontSize: 10, color: "var(--text-secondary)", display: "block", marginBottom: 4 }}>
                Role
              </label>
              <select
                value={newUser.role}
                onChange={(e) => setNewUser((u) => ({ ...u, role: e.target.value }))}
                style={{
                  width: "100%",
                  padding: "8px 12px",
                  borderRadius: 8,
                  border: "1px solid var(--border-color)",
                  background: "var(--bg-primary)",
                  color: "var(--text-primary)",
                  fontSize: 12,
                  outline: "none",
                  boxSizing: "border-box",
                }}
              >
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </div>
          <button
            onClick={handleCreateUser}
            style={{
              padding: "8px 18px",
              borderRadius: 8,
              border: "none",
              background: "linear-gradient(135deg, #ff6688, #dc2626)",
              color: "#fff",
              fontSize: 12,
              fontWeight: 700,
              cursor: "pointer",
              alignSelf: "flex-start",
            }}
          >
            Create User
          </button>
        </div>
      )}

      {msg && (
        <div
          style={{
            padding: "8px 14px",
            borderRadius: 8,
            background: "rgba(59,130,246,0.1)",
            color: "#3b82f6",
            fontSize: 12,
            fontWeight: 600,
            marginBottom: 12,
          }}
        >
          {msg}
        </div>
      )}

      {/* ── Confirm dialog (delete / force logout) ── */}
      <ConfirmDialog
        open={confirmDialog?.open ?? false}
        title={confirmDialog?.title ?? ""}
        message={confirmDialog?.message ?? ""}
        variant={confirmDialog?.variant ?? "danger"}
        confirmLabel={confirmDialog?.confirmLabel ?? "Confirm"}
        cancelLabel="Cancel"
        onConfirm={confirmDialog?.onConfirm ?? closeConfirm}
        onCancel={closeConfirm}
      />

      {/* Filter bar */}
      {!loading && users.length > 0 && (
        <div
          style={{
            background: "var(--bg-primary)",
            border: "1px solid var(--border-color)",
            borderRadius: 10,
            padding: "12px 14px",
            marginBottom: 14,
            display: "flex",
            flexDirection: "column",
            gap: 10,
          }}
        >
          {/* Row 1: Search */}
          <div style={{ position: "relative" }}>
            <span style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)", fontSize: 12, pointerEvents: "none" }}>&#128269;</span>
            <input
              type="text"
              placeholder="Search by name or email..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: "100%", padding: "6px 10px 6px 30px", borderRadius: 8, border: "1px solid var(--border-color)", background: "var(--bg-primary)", color: "var(--text-primary)", fontSize: 12, outline: "none", boxSizing: "border-box" }}
            />
          </div>

          {/* Row 2: Role + MFA + Status + count */}
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
              <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>ROLE:</span>
              {(["ALL", "admin", "analyst", "viewer"] as const).map((r) => {
                const acc: Record<string,string> = { ALL: "#3b82f6", admin: "#ff6688", analyst: "var(--accent-cyan)", viewer: "#00ff88" };
                return <FilterPill key={r} label={r.toUpperCase()} active={roleFilter === r} accent={acc[r]} onClick={() => setRoleFilter(r)} />;
              })}
            </div>

            <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
              <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>MFA:</span>
              {(["ALL", "enabled", "disabled"] as const).map((m) => (
                <FilterPill key={m} label={m === "ALL" ? "All" : m === "enabled" ? "MFA On" : "MFA Off"} active={mfaFilter === m} accent={m === "enabled" ? "#22c55e" : m === "disabled" ? "#ef4444" : "#3b82f6"} onClick={() => setMfaFilter(m)} />
              ))}
            </div>

            <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
              <span style={{ color: "var(--text-muted)", fontSize: 10, fontWeight: 700, letterSpacing: 1, whiteSpace: "nowrap" }}>STATUS:</span>
              {(["ALL", "active", "locked"] as const).map((s) => (
                <FilterPill key={s} label={s === "ALL" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)} active={statusFilter === s} accent={s === "locked" ? "#ef4444" : s === "active" ? "#22c55e" : "#3b82f6"} onClick={() => setStatusFilter(s)} />
              ))}
            </div>

            <span style={{ marginLeft: "auto", color: "var(--text-muted)", fontSize: 11, whiteSpace: "nowrap" }}>
              Showing{" "}
              <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{filteredUsers.length}</span>
              {" of "}
              <span style={{ color: "var(--text-secondary)", fontWeight: 700 }}>{users.length}</span>
              {" users"}
            </span>
            {(searchQuery || roleFilter !== "ALL" || mfaFilter !== "ALL" || statusFilter !== "ALL") && (
              <button onClick={clearFilters} style={{ padding: "3px 10px", borderRadius: 8, border: "1px solid var(--border-color)", background: "transparent", color: "var(--text-secondary)", fontSize: 10, cursor: "pointer", fontWeight: 700 }}>Clear</button>
            )}
          </div>
        </div>
      )}

      {loading ? (
        <div style={{ display: "flex", justifyContent: "center", padding: "32px 0" }}>
          <DualOrbitLoader size={44} label="Loading users..." />
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr>
                {["Username", "Email", "Role", "MFA", "Last Login", "Actions"].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "8px 10px",
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
              {filteredUsers.map((u) => {
                const rc = ROLE_COLORS[u.role] ?? ROLE_COLORS.viewer;
                return (
                  <tr key={u.id} style={{ borderBottom: "1px solid var(--border-color)" }}>
                    <td style={{ padding: "10px 10px", color: "var(--text-primary)", fontWeight: 600 }}>
                      {u.username}
                    </td>
                    <td style={{ padding: "10px 10px", color: "var(--text-muted)" }}>{u.email}</td>
                    <td style={{ padding: "10px 10px" }}>
                      <span
                        style={{
                          padding: "2px 8px",
                          borderRadius: 10,
                          background: rc.bg,
                          color: rc.text,
                          border: `1px solid ${rc.border}`,
                          fontSize: 10,
                          fontWeight: 700,
                        }}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td style={{ padding: "10px 10px" }}>
                      <span
                        style={{
                          fontSize: 10,
                          color: u.two_factor_enabled ? "#22c55e" : "var(--text-secondary)",
                          fontWeight: 700,
                          fontFamily: "'Fira Code', monospace",
                          letterSpacing: 0.5,
                        }}
                      >
                        {u.two_factor_enabled ? "ENABLED" : "DISABLED"}
                      </span>
                    </td>
                    <td style={{ padding: "10px 10px", color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
                      {u.last_login ? new Date(u.last_login).toLocaleDateString() : "Never"}
                    </td>
                    <td style={{ padding: "10px 10px" }}>
                      <div style={{ display: "flex", gap: 6, flexWrap: "nowrap" }}>
                        {/* Change Role — native select avoids absolute-positioning overflow issues in tables */}
                        <select
                          value={u.role}
                          onChange={(e) => handleChangeRole(u.id, e.target.value)}
                          style={{
                            padding: "4px 8px",
                            borderRadius: 6,
                            border: "1px solid var(--border-color-strong)",
                            background: "var(--bg-primary)",
                            color: "var(--accent-cyan)",
                            fontSize: 10,
                            fontWeight: 700,
                            cursor: "pointer",
                            outline: "none",
                            fontFamily: "'Fira Code', monospace",
                          }}
                        >
                          <option value="viewer" style={{ background: "var(--bg-primary)" }}>viewer</option>
                          <option value="analyst" style={{ background: "var(--bg-primary)" }}>analyst</option>
                          <option value="admin" style={{ background: "var(--bg-primary)" }}>admin</option>
                        </select>

                        {/* Delete */}
                        <button
                          onClick={() => handleDelete(u.id, u.username)}
                          style={{
                            padding: "4px 10px",
                            borderRadius: 6,
                            border: "1px solid rgba(239,68,68,0.3)",
                            background: "transparent",
                            color: "#ef4444",
                            fontSize: 10,
                            cursor: "pointer",
                            fontWeight: 700,
                          }}
                        >
                          Delete
                        </button>

                        {/* Force Logout */}
                        <button
                          onClick={() => handleForceLogout(u.id, u.username)}
                          style={{
                            padding: "4px 10px",
                            borderRadius: 6,
                            border: "1px solid rgba(245,158,11,0.3)",
                            background: "transparent",
                            color: "var(--accent-amber)",
                            fontSize: 10,
                            cursor: "pointer",
                            fontWeight: 700,
                            whiteSpace: "nowrap",
                          }}
                        >
                          Logout
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {filteredUsers.length === 0 && (
                <tr>
                  <td
                    colSpan={6}
                    style={{ padding: "20px 10px", textAlign: "center", color: "var(--text-muted)", fontSize: 12 }}
                  >
                    {users.length === 0 ? "No users found." : "No users match current filters."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

// ── Analyst: Case Notes panel ─────────────────────────────────────────────────
interface CaseNote {
  id?: string;
  endpoint_id: string;
  note: string;
  timestamp: string;
}

function CaseNotesPanel({ endpoints }: { endpoints: EndpointInfo[] }) {
  const [notes, setNotes] = useState<CaseNote[]>([]);
  const [noteText, setNoteText] = useState("");
  const [selectedEndpoint, setSelectedEndpoint] = useState(endpoints[0]?.endpoint_id ?? "");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const fetchNotes = useCallback(async () => {
    try {
      const endpoint = selectedEndpoint || "server_host";
      const res = await authAxios.get(`${BACKEND_URL}/case-notes/${endpoint}`);
      setNotes((res.data?.notes ?? res.data ?? []).slice(0, 10));
    } catch {
      // Case notes endpoint may not exist yet
    }
  }, [selectedEndpoint]);

  useEffect(() => { fetchNotes(); }, [fetchNotes]);

  const handleSaveNote = async () => {
    if (!noteText.trim()) return;
    setSaving(true);
    try {
      await authAxios.post(`${BACKEND_URL}/case-notes`, {
        endpoint_id: selectedEndpoint || "general",
        note: noteText.trim(),
        timestamp: new Date().toISOString(),
      });
      setNoteText("");
      setMsg("Note saved.");
      fetchNotes();
    } catch {
      setMsg("Failed to save note — endpoint may not be implemented yet.");
    } finally {
      setSaving(false);
      setTimeout(() => setMsg(null), 3000);
    }
  };

  return (
    <Panel accent="var(--accent-cyan)">
      <span style={SECTION_LABEL}>Case Notes</span>

      <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
        <div>
          <label style={{ fontSize: 11, color: "var(--text-secondary)", display: "block", marginBottom: 6 }}>
            Endpoint
          </label>
          <select
            value={selectedEndpoint}
            onChange={(e) => setSelectedEndpoint(e.target.value)}
            style={{
              padding: "8px 12px",
              borderRadius: 8,
              border: "1px solid var(--border-color)",
              background: "var(--bg-primary)",
              color: "var(--text-primary)",
              fontSize: 12,
              outline: "none",
              width: "100%",
              boxSizing: "border-box",
            }}
          >
            <option value="general">General Investigation</option>
            {endpoints.map((ep) => (
              <option key={ep.endpoint_id} value={ep.endpoint_id}>
                {ep.hostname ?? ep.endpoint_id}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label style={{ fontSize: 11, color: "var(--text-secondary)", display: "block", marginBottom: 6 }}>
            Note
          </label>
          <textarea
            value={noteText}
            onChange={(e) => setNoteText(e.target.value)}
            placeholder="Add note about current investigation..."
            rows={4}
            style={{
              width: "100%",
              padding: "10px 12px",
              borderRadius: 8,
              border: "1px solid var(--border-color)",
              background: "var(--bg-primary)",
              color: "var(--text-primary)",
              fontSize: 12,
              outline: "none",
              resize: "vertical",
              fontFamily: "inherit",
              boxSizing: "border-box",
            }}
          />
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button
            onClick={handleSaveNote}
            disabled={saving || !noteText.trim()}
            style={{
              padding: "9px 20px",
              borderRadius: 8,
              border: "none",
              background:
                saving || !noteText.trim()
                  ? "var(--bg-card)"
                  : "linear-gradient(135deg, #00d4ff, #0284c7)",
              color: saving || !noteText.trim() ? "var(--text-muted)" : "#000",
              fontSize: 12,
              fontWeight: 700,
              cursor: saving || !noteText.trim() ? "not-allowed" : "pointer",
            }}
          >
            {saving ? "Saving..." : "Save Note"}
          </button>
          {msg && (
            <span style={{ fontSize: 12, color: "var(--accent-cyan)", fontWeight: 600 }}>{msg}</span>
          )}
        </div>
      </div>

      {/* Notes list */}
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {notes.length === 0 && (
          <div style={{ color: "var(--text-muted)", fontSize: 12, padding: "8px 0" }}>
            No notes yet. Add the first investigation note above.
          </div>
        )}
        {notes.map((note, i) => (
          <div
            key={note.id ?? i}
            style={{
              padding: "12px 14px",
              background: "var(--bg-primary)",
              border: "1px solid var(--border-color)",
              borderRadius: 8,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                marginBottom: 6,
                gap: 8,
                flexWrap: "wrap",
              }}
            >
              <span
                style={{
                  fontFamily: "'Fira Code', monospace",
                  fontSize: 10,
                  color: "var(--accent-cyan)",
                  fontWeight: 700,
                }}
              >
                {note.endpoint_id}
              </span>
              <span style={{ fontSize: 10, color: "var(--text-secondary)" }}>
                {new Date(note.timestamp).toLocaleString()}
              </span>
            </div>
            <p style={{ margin: 0, fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
              {note.note}
            </p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
interface ProfileViewProps {
  endpoints?: EndpointInfo[];
}

export default function ProfileView({ endpoints = [] }: ProfileViewProps) {
  const { user } = useAuth();

  if (!user) {
    return (
      <div style={{ padding: 32, color: "var(--text-secondary)", fontSize: 14 }}>
        Not authenticated.
      </div>
    );
  }

  const rc = ROLE_COLORS[user.role] ?? ROLE_COLORS.viewer;
  const initials = user.username.slice(0, 2).toUpperCase();

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28 }}
      style={{
        padding: 24,
        maxWidth: 900,
        margin: "0 auto",
        display: "flex",
        flexDirection: "column",
        gap: 20,
      }}
    >
      {/* Page header */}
      <div>
        <h2
          style={{
            margin: 0,
            fontSize: 20,
            fontWeight: 800,
            color: "var(--text-primary)",
            letterSpacing: -0.5,
          }}
        >
          Profile
        </h2>
        <p style={{ margin: "4px 0 0", color: "var(--text-secondary)", fontSize: 13 }}>
          Account information and role-specific management tools.
        </p>
      </div>

      {/* Profile card (all roles) */}
      <Panel accent={rc.text}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 24, flexWrap: "wrap" }}>
          {/* Avatar */}
          <div
            style={{
              width: 72,
              height: 72,
              borderRadius: "50%",
              background: `linear-gradient(135deg, ${rc.text}44, ${rc.text}22)`,
              border: `2px solid ${rc.text}55`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 26,
              fontWeight: 900,
              color: rc.text,
              flexShrink: 0,
              boxShadow: `0 0 20px ${rc.text}22`,
            }}
          >
            {initials}
          </div>

          {/* Info */}
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontSize: 20, fontWeight: 800, color: "var(--text-primary)", marginBottom: 6 }}>
              {user.username}
            </div>
            <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 10 }}>
              {user.email}
            </div>

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              <span
                style={{
                  padding: "4px 12px",
                  borderRadius: 12,
                  background: rc.bg,
                  color: rc.text,
                  border: `1px solid ${rc.border}`,
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: 1,
                  textTransform: "uppercase",
                }}
              >
                {user.role}
              </span>

              <span
                style={{
                  padding: "4px 12px",
                  borderRadius: 12,
                  background: user.two_factor_enabled
                    ? "rgba(34,197,94,0.1)"
                    : "rgba(239,68,68,0.1)",
                  color: user.two_factor_enabled ? "#22c55e" : "#ef4444",
                  border: `1px solid ${user.two_factor_enabled ? "rgba(34,197,94,0.3)" : "rgba(239,68,68,0.3)"}`,
                  fontSize: 11,
                  fontWeight: 700,
                }}
              >
                MFA {user.two_factor_enabled ? "Enabled" : "Disabled"}
              </span>
            </div>

            <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6, maxWidth: 480 }}>
              {ROLE_DESC[user.role]}
            </div>
          </div>

          {/* Stats column */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 10,
              minWidth: 160,
            }}
          >
            <div
              style={{
                background: "var(--bg-primary)",
                border: "1px solid var(--border-color)",
                borderRadius: 10,
                padding: "12px 16px",
              }}
            >
              <div style={{ fontSize: 9, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: 1, fontWeight: 700 }}>
                Last Login
              </div>
              <div style={{ fontSize: 12, color: "var(--text-primary)", marginTop: 4, fontFamily: "'Fira Code', monospace" }}>
                {user.last_login
                  ? new Date(user.last_login).toLocaleString()
                  : "Not available"}
              </div>
            </div>

            <div
              style={{
                background: "var(--bg-primary)",
                border: "1px solid var(--border-color)",
                borderRadius: 10,
                padding: "12px 16px",
              }}
            >
              <div style={{ fontSize: 9, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: 1, fontWeight: 700 }}>
                Member Since
              </div>
              <div style={{ fontSize: 12, color: "var(--text-primary)", marginTop: 4, fontFamily: "'Fira Code', monospace" }}>
                {new Date(user.created_at).toLocaleDateString()}
              </div>
            </div>
          </div>
        </div>
      </Panel>

      {/* Admin: User Management */}
      {user.role === "admin" && <UserManagementPanel />}

      {/* Admin: MFA Recovery Requests */}
      {user.role === "admin" && <MFARecoveryPanel />}

      {/* Analyst: Case Notes */}
      {user.role === "analyst" && <CaseNotesPanel endpoints={endpoints} />}

      {/* Viewer: informational note */}
      {user.role === "viewer" && (
        <Panel accent="var(--text-secondary)">
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 20, color: "var(--text-secondary)" }}>◉</span>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: "var(--text-muted)", marginBottom: 4 }}>
                Read-Only Access
              </div>
              <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Your viewer role grants dashboard access only. Contact an admin to request
                elevated permissions.
              </div>
            </div>
          </div>
        </Panel>
      )}
    </motion.div>
  );
}
