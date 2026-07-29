import React, { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { io, Socket } from 'socket.io-client';
import { AuditEvent } from '../types/auth';
import { authAxios } from '../services/authService';
import { BACKEND_URL } from '../config';
const MAX_AUDIT_ROWS = 200;

interface AuditLogPanelProps {
  /** If provided, use a shared socket; otherwise create own connection */
  socket?: Socket;
}

export default function AuditLogPanel({ socket: externalSocket }: AuditLogPanelProps) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [filter, setFilter] = useState<'ALL' | 'success' | 'failure'>('ALL');
  const [loadingHistory, setLoadingHistory] = useState(false);
  const socketRef = useRef<Socket | null>(null);

  const addEvents = useCallback((incoming: AuditEvent[]) => {
    setEvents((prev) => {
      // Deduplicate by id — newer entries overwrite older if id collides
      const map = new Map<string, AuditEvent>(prev.map((e) => [e.id, e]));
      for (const ev of incoming) {
        map.set(ev.id, ev);
      }
      // Sort newest-first and cap
      return Array.from(map.values())
        .sort((a, b) => (b.timestamp ?? "").localeCompare(a.timestamp ?? ""))
        .slice(0, MAX_AUDIT_ROWS);
    });
  }, []);

  // Auto-fetch history on mount so the panel is never empty on first open
  useEffect(() => {
    handleLoadHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // Use shared socket if provided, else open own
    const sock = externalSocket ?? io(BACKEND_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 2000,
    });
    socketRef.current = sock;

    sock.on('audit_event', (data: AuditEvent) => {
      addEvents([data]);
    });

    // SOAR forensic audit trail — command_result events
    sock.on('command_result', (data: any) => {
      const ev: AuditEvent = {
        id: `cmd_${data.command_id ?? data.action ?? "cmd"}_${Date.now()}`,
        timestamp: data.ts ?? new Date().toISOString(),
        user: 'SOAR',
        action: `${data.action ?? 'command'} → ${data.status ?? 'unknown'}`,
        ip: data.endpoint_id ?? '',
        status: (data.status === 'completed' || data.status === 'success') ? 'success' : 'failure',
        detail: data.message ?? data.result_message ?? '',
      };
      addEvents([ev]);
    });

    // Response execution audit events
    sock.on('response_executed', (data: any) => {
      const actions: string[] = Array.isArray(data.actions)
        ? data.actions
        : Array.isArray(data.command_ids)
        ? [`${data.command_ids.length} commands queued`]
        : ['response executed'];
      const ev: AuditEvent = {
        id: `resp_${data.plan_id ?? 'plan'}_${Date.now()}`,
        timestamp: new Date().toISOString(),
        user: data.issued_by ?? 'System',
        action: `Response executed: ${actions.join(', ')}`,
        ip: data.endpoint_id ?? '',
        status: 'success',
        detail: data.plan_id ? `Plan: ${data.plan_id}` : '',
      };
      addEvents([ev]);
    });

    return () => {
      sock.off('audit_event');
      sock.off('command_result');
      sock.off('response_executed');
      if (!externalSocket) {
        sock.disconnect();
      }
    };
  }, [externalSocket, addEvents]);

  // Load historical events from both security_events (401/403 errors) and
  // audit_logs (login, logout, SOAR, role changes) collections, then merge.
  const handleLoadHistory = useCallback(async () => {
    setLoadingHistory(true);
    try {
      const results: AuditEvent[] = [];

      // Security events — failed auth, 403 access denials
      try {
        const r1 = await authAxios.get(`${BACKEND_URL}/security/events`, {
          params: { limit: 100 },
          timeout: 10000,
        });
        const rawEvents: any[] = r1.data?.events ?? r1.data ?? [];
        rawEvents.forEach((e: any, idx: number) => {
          results.push({
            id: e._id ?? e.id ?? `sec_${idx}_${Date.now()}`,
            timestamp: e.timestamp ?? e.created_at ?? new Date().toISOString(),
            user: e.user_id ?? e.user ?? e.email ?? '—',
            action: e.action ?? e.event_type ?? 'security_event',
            ip: e.ip ?? e.ip_address ?? '—',
            status: (e.status === 'success' || e.severity === 'LOW' || e.status === 200) ? 'success' : 'failure',
            detail: e.detail ?? e.message ?? e.severity ?? '',
          });
        });
      } catch {
        // Silently fail — security/events may be unavailable or empty
      }

      // Auth audit events — login, logout, 2FA, SOAR commands, threshold changes
      try {
        const r2 = await authAxios.get(`${BACKEND_URL}/audit-logs`, {
          params: { limit: 100 },
          timeout: 10000,
        });
        const rawItems: any[] = r2.data?.events ?? r2.data?.logs ?? r2.data ?? [];
        rawItems.forEach((e: any, idx: number) => {
          results.push({
            id: e._id ?? e.id ?? `aud_${idx}_${Date.now()}`,
            timestamp: e.timestamp ?? e.created_at ?? new Date().toISOString(),
            user: e.user_id ?? e.user ?? e.email ?? '—',
            action: e.action ?? e.event_type ?? 'audit_event',
            ip: e.ip ?? e.ip_address ?? '—',
            status: (e.status === 'failure' || e.status === 'fail') ? 'failure' : 'success',
            detail: e.detail ?? e.message ?? e.details ?? '',
          });
        });
      } catch {
        // Silently fail — /audit-logs may not exist on older backend versions
      }

      // Deduplicate by stable key, sort newest-first, cap at MAX_AUDIT_ROWS
      const seen = new Set<string>();
      const deduped = results
        .filter((e) => {
          const key = e.id && !e.id.startsWith('sec_') && !e.id.startsWith('aud_')
            ? e.id
            : `${e.timestamp}_${e.action}_${e.user}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        })
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, MAX_AUDIT_ROWS);

      if (deduped.length > 0) {
        addEvents(deduped);
      }
    } finally {
      setLoadingHistory(false);
    }
  }, [addEvents]);

  const filtered = filter === 'ALL' ? events : events.filter((e) => e.status === filter);
  const successCount = events.filter((e) => e.status === 'success').length;
  const failureCount = events.filter((e) => e.status === 'failure').length;

  return (
    <div
      style={{
        background: 'linear-gradient(135deg, var(--bg-card) 0%, var(--bg-primary) 100%)',
        border: '1px solid var(--border-color-strong)',
        borderRadius: 14,
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        minHeight: 400,
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '14px 20px',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          flexShrink: 0,
          flexWrap: 'wrap',
        }}
      >
        <span
          style={{
            fontSize: 12,
            fontWeight: 700,
            color: 'var(--accent-cyan)',
            letterSpacing: 2,
            textTransform: 'uppercase',
          }}
        >
          Audit Log
        </span>
        <span
          style={{
            background: 'var(--border-color)',
            color: 'var(--accent-cyan)',
            borderRadius: 10,
            padding: '1px 8px',
            fontSize: 10,
            fontWeight: 700,
          }}
        >
          {events.length}
        </span>

        {/* Load History button */}
        <button
          onClick={handleLoadHistory}
          disabled={loadingHistory}
          style={{
            padding: '4px 12px',
            borderRadius: 20,
            border: '1px solid var(--border-color-strong)',
            background: loadingHistory ? 'var(--accent-cyan-dim)' : 'var(--accent-cyan-dim)',
            color: loadingHistory ? 'var(--text-muted)' : 'var(--accent-cyan)',
            fontSize: 10,
            fontWeight: 700,
            cursor: loadingHistory ? 'not-allowed' : 'pointer',
            transition: 'all 0.15s',
            letterSpacing: 0.8,
            textTransform: 'uppercase',
          }}
        >
          {loadingHistory ? 'Loading...' : 'Load History'}
        </button>

        <div style={{ flex: 1 }} />

        {/* Filters */}
        <div style={{ display: 'flex', gap: 6 }}>
          {(['ALL', 'success', 'failure'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '4px 12px',
                borderRadius: 20,
                border: filter === f
                  ? `1px solid ${f === 'failure' ? '#ff3366' : f === 'success' ? '#00ff88' : 'var(--accent-cyan)'}`
                  : '1px solid var(--border-color)',
                background: filter === f
                  ? f === 'failure' ? 'rgba(255,51,102,0.15)' : f === 'success' ? 'rgba(0,255,136,0.1)' : 'var(--border-color)'
                  : 'var(--bg-card)',
                color: filter === f
                  ? f === 'failure' ? '#ff6688' : f === 'success' ? '#00ff88' : 'var(--accent-cyan)'
                  : 'var(--text-secondary)',
                fontSize: 10,
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.15s',
                textTransform: 'uppercase',
                letterSpacing: 0.8,
              }}
            >
              {f === 'ALL' ? `All (${events.length})` : f === 'success' ? `OK (${successCount})` : `Fail (${failureCount})`}
            </button>
          ))}
        </div>
      </div>

      {/* Table header */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '140px 130px 1fr 120px 80px',
          gap: 0,
          padding: '8px 20px',
          background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border-color)',
          flexShrink: 0,
        }}
      >
        {['Time', 'User', 'Action', 'IP', 'Status'].map((col) => (
          <span
            key={col}
            style={{
              fontSize: 9,
              fontWeight: 700,
              color: 'var(--text-muted)',
              letterSpacing: 1.5,
              textTransform: 'uppercase',
            }}
          >
            {col}
          </span>
        ))}
      </div>

      {/* Rows */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.length === 0 ? (
          <div
            style={{
              padding: '48px 20px',
              textAlign: 'center',
              color: 'var(--text-muted)',
              fontSize: 13,
            }}
          >
            No audit events yet — actions like login, logout, and SOAR commands will appear here.
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {filtered.map((event) => (
              <motion.div
                key={event.id}
                initial={{ x: 40, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.2, ease: 'easeOut' }}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '140px 130px 1fr 120px 80px',
                  gap: 0,
                  padding: '10px 20px',
                  borderBottom: '1px solid var(--border-color)',
                  alignItems: 'center',
                  background:
                    event.status === 'failure'
                      ? 'rgba(255,51,102,0.04)'
                      : 'transparent',
                }}
              >
                {/* Time */}
                <span
                  style={{
                    fontSize: 11,
                    color: 'var(--text-secondary)',
                    fontFamily: 'monospace',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {formatAuditTime(event.timestamp)}
                </span>

                {/* User */}
                <span
                  style={{
                    fontSize: 12,
                    color: event.user === 'SOAR' ? '#f59e0b' : 'var(--text-primary)',
                    fontWeight: 600,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {event.user || '—'}
                </span>

                {/* Action */}
                <span
                  style={{
                    fontSize: 11,
                    color: 'var(--text-secondary)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    paddingRight: 8,
                  }}
                  title={event.detail}
                >
                  {event.action}
                </span>

                {/* IP */}
                <span
                  style={{
                    fontSize: 11,
                    color: 'var(--accent-cyan)',
                    fontFamily: 'monospace',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {event.ip || '—'}
                </span>

                {/* Status chip */}
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: '3px 10px',
                    borderRadius: 20,
                    fontSize: 9,
                    fontWeight: 800,
                    letterSpacing: 1,
                    textTransform: 'uppercase',
                    background:
                      event.status === 'success'
                        ? 'rgba(0,255,136,0.12)'
                        : 'rgba(255,51,102,0.15)',
                    color:
                      event.status === 'success' ? '#00ff88' : '#ff6688',
                    border:
                      event.status === 'success'
                        ? '1px solid rgba(0,255,136,0.3)'
                        : '1px solid rgba(255,51,102,0.4)',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {event.status === 'success' ? 'OK' : 'FAIL'}
                </span>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}

function formatAuditTime(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString('en-GB', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return ts;
  }
}
