// ConfirmDialog.tsx
// Reusable confirmation modal used project-wide.
// Supports three visual variants: danger (red), warning (amber), info (cyan).

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning' | 'info';
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  variant = 'danger',
  onConfirm,
  onCancel,
}) => {
  const accentColor =
    variant === 'danger'  ? '#ff4466' :
    variant === 'warning' ? '#ffaa00' :
                            '#00d4ff';

  const glowColor =
    variant === 'danger'  ? 'rgba(255,68,102,0.3)' :
    variant === 'warning' ? 'rgba(255,170,0,0.3)'  :
                            'rgba(0,212,255,0.3)';

  const icon =
    variant === 'danger'  ? '⚠️' :
    variant === 'warning' ? '🔔' :
                            'ℹ️';

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          key="confirm-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            background: 'rgba(0,0,0,0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          onClick={onCancel}
        >
          <motion.div
            key="confirm-card"
            initial={{ scale: 0.85, opacity: 0, y: -20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.85, opacity: 0, y: -20 }}
            transition={{ type: 'spring', stiffness: 400, damping: 30 }}
            onClick={(e) => e.stopPropagation()}
            style={{
              background: 'rgba(10,17,35,0.98)',
              border: `1px solid ${accentColor}`,
              boxShadow: `0 0 30px ${glowColor}, 0 0 60px rgba(0,0,0,0.5)`,
              borderRadius: 12,
              padding: '28px 32px',
              minWidth: 360,
              maxWidth: 480,
              fontFamily: "'Fira Code', monospace",
            }}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
              <span style={{ fontSize: 20 }}>{icon}</span>
              <span
                style={{
                  color: accentColor,
                  fontWeight: 700,
                  fontSize: 14,
                  letterSpacing: 1,
                }}
              >
                {title}
              </span>
            </div>

            {/* Body */}
            <p
              style={{
                color: '#94a3b8',
                fontSize: 12,
                lineHeight: 1.7,
                margin: '0 0 24px',
              }}
            >
              {message}
            </p>

            {/* Actions */}
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button
                onClick={onCancel}
                style={{
                  padding: '8px 18px',
                  borderRadius: 6,
                  border: '1px solid #334155',
                  background: 'transparent',
                  color: '#94a3b8',
                  fontSize: 11,
                  fontFamily: "'Fira Code', monospace",
                  cursor: 'pointer',
                  fontWeight: 600,
                  letterSpacing: 0.5,
                }}
              >
                {cancelLabel}
              </button>
              <button
                onClick={onConfirm}
                style={{
                  padding: '8px 18px',
                  borderRadius: 6,
                  border: `1px solid ${accentColor}`,
                  background: glowColor,
                  color: accentColor,
                  fontSize: 11,
                  fontFamily: "'Fira Code', monospace",
                  cursor: 'pointer',
                  fontWeight: 700,
                  letterSpacing: 0.5,
                  boxShadow: `0 0 12px ${glowColor}`,
                }}
              >
                {confirmLabel}
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
