// MFARecoveryPanel.tsx
// Admin-only panel: lists pending MFA recovery requests, approve or deny each one.

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'react-hot-toast';
import { getPendingMFARecoveryRequests, approveMFARecovery } from '../../../services/authService';
import DualOrbitLoader from '../../shared/DualOrbitLoader';

// ── Types ─────────────────────────────────────────────────────────────────────
interface MFARecoveryRequest {
  request_id: string;
  email: string;
  username: string;
  role: string;
  reason: string;
  requested_at: string;
  ip_address: string;
  status: 'pending' | 'approved' | 'denied';
}

// ── Toast styles ─────────────────────────────────────────────────────────────
const toastErrStyle = {
  background: '#1a0010',
  color: '#ff6688',
  border: '1px solid rgba(255,51,102,0.4)',
  fontSize: '13px',
  fontFamily: "'Fira Code', monospace",
};
const toastSuccessStyle = {
  background: '#001a10',
  color: '#00ff88',
  border: '1px solid rgba(0,255,136,0.3)',
  fontSize: '13px',
  fontFamily: "'Fira Code', monospace",
};

// ── Role badge ────────────────────────────────────────────────────────────────
const ROLE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  admin:   { bg: 'rgba(255,0,68,0.12)',  text: '#ff6688', border: 'rgba(255,0,68,0.3)' },
  analyst: { bg: 'rgba(0,212,255,0.10)', text: '#00d4ff', border: 'rgba(0,212,255,0.3)' },
  viewer:  { bg: 'rgba(0,255,136,0.08)', text: '#00ff88', border: 'rgba(0,255,136,0.25)' },
};

function RoleBadge({ role }: { role: string }) {
  const c = ROLE_COLORS[role] ?? ROLE_COLORS.viewer;
  return (
    <span
      style={{
        padding: '2px 8px',
        borderRadius: 10,
        fontSize: 9,
        fontWeight: 700,
        fontFamily: "'Fira Code', monospace",
        letterSpacing: 1.2,
        textTransform: 'uppercase',
        background: c.bg,
        color: c.text,
        border: `1px solid ${c.border}`,
      }}
    >
      {role}
    </span>
  );
}

// ── Confirm dialog ────────────────────────────────────────────────────────────
interface ConfirmDialogProps {
  action: 'approve' | 'deny';
  requestId: string;
  email: string;
  onConfirm: () => void;
  onCancel: () => void;
  loading: boolean;
}

function ConfirmDialog({ action, requestId, email, onConfirm, onCancel, loading }: ConfirmDialogProps) {
  const isApprove = action === 'approve';
  const accentColor = isApprove ? '#00ff88' : '#ff4444';
  const accentBg = isApprove ? 'rgba(0,255,136,0.08)' : 'rgba(255,68,68,0.08)';
  const accentBorder = isApprove ? 'rgba(0,255,136,0.3)' : 'rgba(255,68,68,0.3)';

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        backdropFilter: 'blur(4px)',
      }}
      onClick={onCancel}
    >
      <motion.div
        initial={{ scale: 0.9, y: 20 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.9, y: 20 }}
        transition={{ type: 'spring', stiffness: 320, damping: 26 }}
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'rgba(0,20,40,0.97)',
          border: `1px solid ${accentBorder}`,
          borderRadius: 14,
          padding: '32px 36px',
          maxWidth: 400,
          width: '90%',
          boxShadow: `0 0 40px rgba(${isApprove ? '0,255,136' : '255,68,68'},0.25)`,
        }}
      >
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <div
            style={{
              width: 52,
              height: 52,
              borderRadius: '50%',
              background: accentBg,
              border: `2px solid ${accentBorder}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 14px',
            }}
          >
            {isApprove ? (
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={accentColor} strokeWidth="2.5">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            ) : (
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={accentColor} strokeWidth="2.5">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            )}
          </div>
          <p
            style={{
              margin: '0 0 6px',
              fontFamily: "'Fira Code', monospace",
              fontSize: 14,
              fontWeight: 700,
              color: accentColor,
              letterSpacing: 1,
            }}
          >
            {isApprove ? 'Approve MFA Recovery?' : 'Deny MFA Recovery?'}
          </p>
          <p style={{ margin: 0, fontSize: 12, color: '#94a3b8', fontFamily: "'Fira Code', monospace", lineHeight: 1.7 }}>
            {isApprove
              ? `This will reset MFA for ${email} and allow re-enrolment.`
              : `The recovery request from ${email} will be permanently denied.`}
          </p>
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            style={{
              flex: 1,
              padding: '10px',
              borderRadius: 8,
              border: '1px solid rgba(51,65,85,0.6)',
              background: 'transparent',
              color: '#6b8fa3',
              fontSize: 12,
              fontWeight: 700,
              fontFamily: "'Fira Code', monospace",
              cursor: 'pointer',
              letterSpacing: 1,
            }}
          >
            Cancel
          </button>
          <motion.button
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            type="button"
            onClick={onConfirm}
            disabled={loading}
            style={{
              flex: 1,
              padding: '10px',
              borderRadius: 8,
              border: 'none',
              background: isApprove
                ? 'linear-gradient(135deg, #00ff88, #00cc66)'
                : 'linear-gradient(135deg, #ff4444, #cc0000)',
              color: '#050b18',
              fontSize: 12,
              fontWeight: 900,
              fontFamily: "'Fira Code', monospace",
              cursor: loading ? 'not-allowed' : 'pointer',
              letterSpacing: 1.5,
              textTransform: 'uppercase',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 6,
            }}
          >
            {loading ? (
              <motion.span
                animate={{ rotate: 360 }}
                transition={{ duration: 0.9, repeat: Infinity, ease: 'linear' }}
                style={{ display: 'inline-block', fontSize: 13 }}
              >
                ⟳
              </motion.span>
            ) : null}
            {loading ? '...' : isApprove ? 'Approve' : 'Deny'}
          </motion.button>
        </div>
      </motion.div>
    </motion.div>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────
function EmptyState() {
  return (
    <div
      style={{
        textAlign: 'center',
        padding: '40px 24px',
        color: '#475569',
      }}
    >
      <svg
        width="40"
        height="40"
        viewBox="0 0 24 24"
        fill="none"
        stroke="#334155"
        strokeWidth="1.5"
        style={{ margin: '0 auto 12px', display: 'block' }}
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <polyline points="9 12 11 14 15 10" />
      </svg>
      <p
        style={{
          margin: 0,
          fontFamily: "'Fira Code', monospace",
          fontSize: 12,
          color: '#475569',
          letterSpacing: 0.5,
        }}
      >
        No pending recovery requests
      </p>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function MFARecoveryPanel() {
  const [requests, setRequests] = useState<MFARecoveryRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  // Confirm dialog state
  const [confirmTarget, setConfirmTarget] = useState<{
    requestId: string;
    email: string;
    action: 'approve' | 'deny';
  } | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchRequests = useCallback(async () => {
    try {
      const data = await getPendingMFARecoveryRequests();
      setRequests(Array.isArray(data) ? data : []);
      setLastRefresh(new Date());
    } catch {
      // Silently fail — banner will show on first load only
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRequests();
    intervalRef.current = setInterval(fetchRequests, 30_000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchRequests]);

  const handleAction = async () => {
    if (!confirmTarget) return;
    setActionLoading(true);
    try {
      await approveMFARecovery(confirmTarget.requestId, confirmTarget.action);
      toast.success(
        confirmTarget.action === 'approve'
          ? `MFA recovery approved for ${confirmTarget.email}`
          : `Recovery request denied for ${confirmTarget.email}`,
        { style: confirmTarget.action === 'approve' ? toastSuccessStyle : toastErrStyle }
      );
      setRequests((prev) => prev.filter((r) => r.request_id !== confirmTarget.requestId));
      setConfirmTarget(null);
    } catch (err: unknown) {
      const msg = extractMsg(err);
      toast.error(msg, { style: toastErrStyle });
    } finally {
      setActionLoading(false);
    }
  };

  const pendingCount = requests.length;

  return (
    <>
      {/* Confirm dialog overlay */}
      <AnimatePresence>
        {confirmTarget && (
          <ConfirmDialog
            action={confirmTarget.action}
            requestId={confirmTarget.requestId}
            email={confirmTarget.email}
            onConfirm={handleAction}
            onCancel={() => setConfirmTarget(null)}
            loading={actionLoading}
          />
        )}
      </AnimatePresence>

      <div
        style={{
          background: 'linear-gradient(135deg, #1e293b, #162032)',
          borderLeft: '4px solid #ff6644',
          borderRadius: 12,
          padding: '24px 28px',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Accent circle */}
        <div
          style={{
            position: 'absolute',
            top: -20,
            right: -20,
            width: 80,
            height: 80,
            borderRadius: '50%',
            background: 'rgba(255,100,0,0.05)',
            pointerEvents: 'none',
          }}
        />

        {/* Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 18,
            flexWrap: 'wrap',
            gap: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#ff6644"
              strokeWidth="2"
            >
              <rect x="3" y="11" width="18" height="11" rx="2" />
              <path d="M7 11V7a5 5 0 018-4" stroke="#ff4444" />
              <line x1="15" y1="3" x2="17" y2="1" stroke="#ffaa00" strokeWidth="2.5" strokeLinecap="round" />
            </svg>
            <span
              style={{
                fontFamily: "'Fira Code', monospace",
                fontSize: 12,
                fontWeight: 700,
                color: '#e0f4ff',
                letterSpacing: 1.5,
                textTransform: 'uppercase',
              }}
            >
              MFA Recovery Requests
            </span>
            {pendingCount > 0 && (
              <motion.span
                animate={{ opacity: [1, 0.6, 1] }}
                transition={{ duration: 1.8, repeat: Infinity }}
                style={{
                  padding: '2px 8px',
                  borderRadius: 10,
                  fontSize: 11,
                  fontWeight: 700,
                  background: 'rgba(255,100,0,0.15)',
                  color: '#ff6644',
                  border: '1px solid rgba(255,100,0,0.35)',
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                {pendingCount}
              </motion.span>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span
              style={{
                fontSize: 10,
                color: '#475569',
                fontFamily: "'Fira Code', monospace",
              }}
            >
              Last refresh: {lastRefresh.toLocaleTimeString()}
            </span>
            <button
              type="button"
              onClick={fetchRequests}
              disabled={loading}
              style={{
                background: 'rgba(0,212,255,0.06)',
                border: '1px solid rgba(0,212,255,0.2)',
                borderRadius: 6,
                padding: '5px 10px',
                color: '#00d4ff',
                fontSize: 10,
                fontWeight: 700,
                fontFamily: "'Fira Code', monospace",
                cursor: 'pointer',
                letterSpacing: 1,
                textTransform: 'uppercase',
              }}
            >
              Refresh
            </button>
          </div>
        </div>

        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '36px 0' }}>
            <DualOrbitLoader size={44} label="Loading requests..." />
          </div>
        ) : requests.length === 0 ? (
          <EmptyState />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 640 }}>
              <thead>
                <tr>
                  {['User', 'Email', 'Role', 'Requested At', 'IP', 'Reason', 'Actions'].map((h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: 'left',
                        padding: '8px 12px',
                        fontSize: 9,
                        fontWeight: 700,
                        color: '#475569',
                        letterSpacing: 2,
                        textTransform: 'uppercase',
                        fontFamily: "'Fira Code', monospace",
                        borderBottom: '1px solid rgba(0,212,255,0.08)',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {requests.map((req, i) => (
                    <motion.tr
                      key={req.request_id}
                      initial={{ opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, x: 20 }}
                      transition={{ delay: i * 0.05 }}
                      style={{
                        borderBottom: '1px solid rgba(0,212,255,0.05)',
                      }}
                    >
                      <td style={tdStyle}>
                        <span style={{ color: '#e0f4ff', fontSize: 12, fontFamily: "'Fira Code', monospace" }}>
                          {req.username}
                        </span>
                      </td>
                      <td style={tdStyle}>
                        <span style={{ color: '#94a3b8', fontSize: 11, fontFamily: "'Fira Code', monospace" }}>
                          {req.email}
                        </span>
                      </td>
                      <td style={tdStyle}>
                        <RoleBadge role={req.role} />
                      </td>
                      <td style={tdStyle}>
                        <span style={{ color: '#6b8fa3', fontSize: 11, fontFamily: "'Fira Code', monospace", whiteSpace: 'nowrap' }}>
                          {new Date(req.requested_at).toLocaleString()}
                        </span>
                      </td>
                      <td style={tdStyle}>
                        <code style={{ color: '#6b8fa3', fontSize: 11, fontFamily: "'Fira Code', monospace" }}>
                          {req.ip_address}
                        </code>
                      </td>
                      <td style={{ ...tdStyle, maxWidth: 200 }}>
                        <span
                          style={{
                            color: '#94a3b8',
                            fontSize: 11,
                            fontFamily: "'Fira Code', monospace",
                            display: '-webkit-box',
                            WebkitLineClamp: 2,
                            WebkitBoxOrient: 'vertical',
                            overflow: 'hidden',
                          }}
                          title={req.reason}
                        >
                          {req.reason}
                        </span>
                      </td>
                      <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                        <div style={{ display: 'flex', gap: 8 }}>
                          <motion.button
                            whileHover={{ scale: 1.06 }}
                            whileTap={{ scale: 0.94 }}
                            type="button"
                            onClick={() =>
                              setConfirmTarget({
                                requestId: req.request_id,
                                email: req.email,
                                action: 'approve',
                              })
                            }
                            style={{
                              padding: '5px 12px',
                              borderRadius: 6,
                              border: '1px solid rgba(0,255,136,0.4)',
                              background: 'rgba(0,255,136,0.08)',
                              color: '#00ff88',
                              fontSize: 10,
                              fontWeight: 700,
                              fontFamily: "'Fira Code', monospace",
                              cursor: 'pointer',
                              letterSpacing: 1,
                              textTransform: 'uppercase',
                            }}
                          >
                            Approve
                          </motion.button>
                          <motion.button
                            whileHover={{ scale: 1.06 }}
                            whileTap={{ scale: 0.94 }}
                            type="button"
                            onClick={() =>
                              setConfirmTarget({
                                requestId: req.request_id,
                                email: req.email,
                                action: 'deny',
                              })
                            }
                            style={{
                              padding: '5px 12px',
                              borderRadius: 6,
                              border: '1px solid rgba(255,68,68,0.4)',
                              background: 'rgba(255,68,68,0.08)',
                              color: '#ff4444',
                              fontSize: 10,
                              fontWeight: 700,
                              fontFamily: "'Fira Code', monospace",
                              cursor: 'pointer',
                              letterSpacing: 1,
                              textTransform: 'uppercase',
                            }}
                          >
                            Deny
                          </motion.button>
                        </div>
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

const tdStyle: React.CSSProperties = {
  padding: '10px 12px',
  verticalAlign: 'middle',
};

function extractMsg(err: unknown): string {
  if (err && typeof err === 'object' && 'response' in err) {
    const e = err as { response?: { data?: { detail?: unknown } } };
    const d = e.response?.data?.detail;
    if (typeof d === 'string') return d;
  }
  if (err instanceof Error) return err.message;
  return 'Action failed';
}
