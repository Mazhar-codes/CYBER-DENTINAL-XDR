// SecurityRecoveryTimeline.tsx
// Reusable animated neon timeline for security recovery events.

import React from 'react';
import { motion } from 'framer-motion';

export interface TimelineEvent {
  time: string;
  label: string;
  status: 'completed' | 'in-progress' | 'pending';
  severity?: 'info' | 'warning' | 'high';
}

export interface SecurityRecoveryTimelineProps {
  events: TimelineEvent[];
  title?: string;
}

const STATUS_COLOR: Record<TimelineEvent['status'], string> = {
  completed: '#00ff88',
  'in-progress': '#00d4ff',
  pending: '#334155',
};

const SEVERITY_ACCENT: Record<NonNullable<TimelineEvent['severity']>, string> = {
  info: '#00d4ff',
  warning: '#ffaa00',
  high: '#ff4444',
};

function TimelineDot({ status }: { status: TimelineEvent['status'] }) {
  const color = STATUS_COLOR[status];

  if (status === 'completed') {
    return (
      <div
        style={{
          width: 20,
          height: 20,
          borderRadius: '50%',
          background: 'rgba(0,255,136,0.15)',
          border: `2px solid ${color}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          boxShadow: `0 0 8px rgba(0,255,136,0.4)`,
        }}
      >
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="3">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      </div>
    );
  }

  if (status === 'in-progress') {
    return (
      <motion.div
        animate={{ boxShadow: ['0 0 4px rgba(0,212,255,0.4)', '0 0 16px rgba(0,212,255,0.9)', '0 0 4px rgba(0,212,255,0.4)'] }}
        transition={{ duration: 1.2, repeat: Infinity }}
        style={{
          width: 20,
          height: 20,
          borderRadius: '50%',
          background: 'rgba(0,212,255,0.2)',
          border: `2px solid ${color}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}
      >
        <motion.div
          animate={{ scale: [0.5, 1, 0.5] }}
          transition={{ duration: 1.2, repeat: Infinity }}
          style={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: color,
          }}
        />
      </motion.div>
    );
  }

  // pending
  return (
    <div
      style={{
        width: 20,
        height: 20,
        borderRadius: '50%',
        background: 'transparent',
        border: `2px solid ${color}`,
        flexShrink: 0,
      }}
    />
  );
}

export default function SecurityRecoveryTimeline({
  events,
  title,
}: SecurityRecoveryTimelineProps) {
  return (
    <div
      style={{
        background: 'rgba(0,10,30,0.7)',
        border: '1px solid rgba(0,212,255,0.15)',
        borderRadius: 12,
        padding: '20px 24px',
      }}
    >
      {title && (
        <p
          style={{
            margin: '0 0 20px',
            fontSize: 10,
            fontWeight: 700,
            color: '#475569',
            letterSpacing: 2,
            textTransform: 'uppercase',
            fontFamily: "'Fira Code', monospace",
          }}
        >
          {title}
        </p>
      )}

      <div style={{ position: 'relative' }}>
        {/* Vertical neon line */}
        <div
          style={{
            position: 'absolute',
            left: 9,
            top: 10,
            bottom: 10,
            width: 2,
            background: 'linear-gradient(to bottom, rgba(0,255,136,0.6), rgba(0,212,255,0.4), rgba(51,65,85,0.2))',
            borderRadius: 1,
          }}
        />

        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, paddingLeft: 4 }}>
          {events.map((event, i) => {
            const accentColor = event.severity
              ? SEVERITY_ACCENT[event.severity]
              : STATUS_COLOR[event.status];

            return (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -12 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.1, duration: 0.35, ease: 'easeOut' }}
                style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}
              >
                <TimelineDot status={event.status} />

                <div style={{ flex: 1, paddingTop: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <span
                      style={{
                        fontFamily: "'Fira Code', monospace",
                        fontSize: 13,
                        fontWeight: 600,
                        color: event.status === 'pending' ? '#475569' : '#e0f4ff',
                        letterSpacing: 0.3,
                      }}
                    >
                      {event.label}
                    </span>
                    {event.status === 'in-progress' && (
                      <span
                        style={{
                          fontFamily: "'Fira Code', monospace",
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: 1.5,
                          color: '#00d4ff',
                          background: 'rgba(0,212,255,0.08)',
                          border: '1px solid rgba(0,212,255,0.25)',
                          borderRadius: 10,
                          padding: '1px 8px',
                          textTransform: 'uppercase',
                        }}
                      >
                        In Progress
                      </span>
                    )}
                  </div>
                  {event.time && (
                    <span
                      style={{
                        fontFamily: "'Fira Code', monospace",
                        fontSize: 10,
                        color: '#334155',
                        letterSpacing: 0.5,
                        marginTop: 2,
                        display: 'block',
                      }}
                    >
                      {event.time}
                    </span>
                  )}
                </div>

                {/* Severity accent dot */}
                {event.severity && event.severity !== 'info' && (
                  <div
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: '50%',
                      background: accentColor,
                      marginTop: 7,
                      flexShrink: 0,
                      boxShadow: `0 0 6px ${accentColor}`,
                    }}
                  />
                )}
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
