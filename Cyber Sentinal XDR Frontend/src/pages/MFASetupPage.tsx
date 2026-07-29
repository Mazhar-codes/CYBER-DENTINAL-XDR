import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'react-hot-toast';
import { enable2FA, verify2FASetup, clearTokens } from '../services/authService';
import { MFASetupResponse } from '../types/auth';
import OTPInput from '../components/OTPInput';
import DualOrbitLoader from '../components/shared/DualOrbitLoader';

export default function MFASetupPage() {
  const navigate = useNavigate();
  const [mfaData, setMfaData] = useState<MFASetupResponse | null>(null);
  const [otp, setOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const [fetching, setFetching] = useState(true);
  const [backupCopied, setBackupCopied] = useState(false);
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [backupAcknowledged, setBackupAcknowledged] = useState(false);

  useEffect(() => {
    const fetchSetup = async () => {
      try {
        const data = await enable2FA();
        setMfaData(data);
        if (data.backup_codes && data.backup_codes.length > 0) {
          setShowBackupCodes(true);
        }
      } catch {
        toast.error('Failed to initialize 2FA setup', {
          style: { background: '#1a0010', color: '#ff6688', border: '1px solid rgba(255,51,102,0.4)' },
        });
      } finally {
        setFetching(false);
      }
    };
    fetchSetup();
  }, []);

  const formatSecret = (secret: string): string => {
    return secret.match(/.{1,4}/g)?.join(' ') ?? secret;
  };

  const copyBackupCodes = () => {
    if (!mfaData?.backup_codes) return;
    navigator.clipboard.writeText(mfaData.backup_codes.join('\n')).then(() => {
      setBackupCopied(true);
      setTimeout(() => setBackupCopied(false), 2500);
      toast.success('Backup codes copied to clipboard', {
        style: { background: '#001a10', color: '#00ff88', border: '1px solid rgba(0,255,136,0.3)' },
      });
    });
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (otp.length < 6) {
      toast.error('Enter all 6 digits', { style: { background: '#1a0010', color: '#ff6688' } });
      return;
    }
    if (mfaData?.backup_codes?.length && !backupAcknowledged) {
      toast.error('Please save your backup codes and check the box to continue', {
        style: { background: '#1a0010', color: '#ff6688' },
      });
      return;
    }
    setLoading(true);
    try {
      await verify2FASetup(otp);
      // Backend revokes all pre-2FA sessions on activation — clear local tokens
      // and redirect to login so the user re-authenticates through the full OTP flow.
      clearTokens();
      toast.success('2FA enabled! Please log in again with your authenticator.', {
        duration: 5000,
        style: { background: '#001a10', color: '#00ff88', border: '1px solid rgba(0,255,136,0.3)' },
      });
      navigate('/login');
    } catch {
      toast.error('Invalid OTP — try again', { style: { background: '#1a0010', color: '#ff6688' } });
      setOtp('');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#050b18',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
      }}
    >
      <motion.div
        initial={{ y: 40, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 200, damping: 22 }}
        style={{
          width: '100%',
          maxWidth: 460,
          background: 'rgba(0,20,40,0.85)',
          backdropFilter: 'blur(20px)',
          border: '1px solid rgba(0,212,255,0.3)',
          borderRadius: 16,
          boxShadow: '0 0 30px rgba(0,212,255,0.15)',
          padding: '40px 36px',
        }}
      >
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>🔐</div>
          <h1
            style={{
              margin: 0,
              color: '#00d4ff',
              fontSize: 18,
              fontWeight: 900,
              letterSpacing: 3,
              textTransform: 'uppercase',
              fontFamily: "'Fira Code', monospace",
              textShadow: '0 0 12px rgba(0,212,255,0.5)',
            }}
          >
            Two-Factor Setup
          </h1>
          <p style={{ color: '#6b8fa3', fontSize: 12, margin: '8px 0 0', letterSpacing: 0.5 }}>
            Secure your account with an authenticator app
          </p>
        </div>

        {fetching ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '40px 0' }}>
            <DualOrbitLoader size={52} label="Generating secret key..." />
          </div>
        ) : mfaData ? (
          <form onSubmit={handleVerify} style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            {/* Step 1: Scan QR */}
            <StepCard number={1} title="Scan QR Code">
              <p style={{ color: '#94a3b8', fontSize: 12, margin: '0 0 16px' }}>
                Open your authenticator app (Google Authenticator, Authy, 1Password) and scan this QR code.
              </p>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  padding: 16,
                  background: '#ffffff',
                  borderRadius: 12,
                  width: 'fit-content',
                  margin: '0 auto',
                  boxShadow: '0 0 20px rgba(0,212,255,0.2)',
                }}
              >
                <img
                  src={`data:image/png;base64,${mfaData.qr_code_base64}`}
                  alt="QR Code for 2FA setup"
                  style={{ width: 160, height: 160, display: 'block' }}
                />
              </div>
            </StepCard>

            {/* Step 2: Manual key */}
            <StepCard number={2} title="Or Enter Manually">
              <p style={{ color: '#94a3b8', fontSize: 12, margin: '0 0 10px' }}>
                If you cannot scan the QR code, enter this secret key manually:
              </p>
              <div
                style={{
                  background: 'rgba(0,0,0,0.4)',
                  border: '1px solid rgba(0,212,255,0.2)',
                  borderRadius: 8,
                  padding: '10px 14px',
                  fontFamily: "'Fira Code', monospace",
                  fontSize: 14,
                  color: '#00d4ff',
                  letterSpacing: 2,
                  wordBreak: 'break-all',
                  userSelect: 'all',
                  textAlign: 'center',
                }}
              >
                {formatSecret(mfaData.secret)}
              </div>
              <p style={{ color: '#475569', fontSize: 10, margin: '6px 0 0', textAlign: 'center', letterSpacing: 0.5 }}>
                Click to select all — keep this secret safe
              </p>
            </StepCard>

            {/* Step 3: Backup codes */}
            <AnimatePresence>
              {showBackupCodes && mfaData?.backup_codes && mfaData.backup_codes.length > 0 && (
                <motion.div
                  key="backup-codes"
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                >
                  <StepCard number={3} title="Save Backup Codes">
                    <p style={{ color: '#f59e0b', fontSize: 11, margin: '0 0 10px', fontWeight: 700, letterSpacing: 0.5 }}>
                      IMPORTANT: Store these codes in a safe place. Each code can only be used once.
                    </p>
                    <div
                      style={{
                        background: 'rgba(0,0,0,0.5)',
                        border: '1px solid rgba(245,158,11,0.3)',
                        borderRadius: 8,
                        padding: '10px 14px',
                        display: 'grid',
                        gridTemplateColumns: '1fr 1fr',
                        gap: '4px 16px',
                        marginBottom: 10,
                      }}
                    >
                      {mfaData.backup_codes.map((code, i) => (
                        <span
                          key={i}
                          style={{
                            fontFamily: "'Fira Code', monospace",
                            fontSize: 13,
                            color: '#e2e8f0',
                            letterSpacing: 2,
                            padding: '2px 0',
                          }}
                        >
                          {code}
                        </span>
                      ))}
                    </div>
                    <button
                      type="button"
                      onClick={copyBackupCodes}
                      style={{
                        width: '100%',
                        padding: '8px 14px',
                        borderRadius: 6,
                        border: '1px solid rgba(245,158,11,0.4)',
                        background: backupCopied ? 'rgba(16,185,129,0.15)' : 'rgba(245,158,11,0.08)',
                        color: backupCopied ? '#10b981' : '#f59e0b',
                        fontSize: 11,
                        fontWeight: 700,
                        letterSpacing: 1,
                        cursor: 'pointer',
                        fontFamily: "'Fira Code', monospace",
                        marginBottom: 10,
                        transition: 'all 0.2s',
                      }}
                    >
                      {backupCopied ? 'COPIED!' : 'COPY ALL CODES'}
                    </button>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={backupAcknowledged}
                        onChange={(e) => setBackupAcknowledged(e.target.checked)}
                        style={{ accentColor: '#00d4ff', width: 14, height: 14, cursor: 'pointer' }}
                      />
                      <span style={{ color: '#94a3b8', fontSize: 11, fontFamily: "'Fira Code', monospace" }}>
                        I have saved these backup codes in a secure location
                      </span>
                    </label>
                  </StepCard>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Step 4: Verify */}
            <StepCard number={mfaData?.backup_codes?.length ? 4 : 3} title="Verify Code">
              <p style={{ color: '#94a3b8', fontSize: 12, margin: '0 0 16px' }}>
                Enter the 6-digit code shown in your authenticator app to confirm setup.
              </p>
              <OTPInput value={otp} onChange={setOtp} disabled={loading} />
            </StepCard>

            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              type="submit"
              disabled={loading || otp.length < 6}
              style={{
                padding: '12px 24px',
                borderRadius: 8,
                border: 'none',
                background:
                  loading || otp.length < 6
                    ? 'rgba(0,50,80,0.5)'
                    : 'linear-gradient(135deg, #00d4ff 0%, #0066ff 100%)',
                color: loading || otp.length < 6 ? '#6b8fa3' : '#050b18',
                fontWeight: 900,
                fontSize: 13,
                letterSpacing: 2,
                textTransform: 'uppercase',
                cursor: loading || otp.length < 6 ? 'not-allowed' : 'pointer',
                boxShadow: otp.length === 6 ? '0 0 20px rgba(0,212,255,0.4)' : 'none',
                fontFamily: "'Fira Code', monospace",
              }}
            >
              {loading ? 'Verifying...' : 'Enable 2FA'}
            </motion.button>

            <button
              type="button"
              onClick={() => navigate('/dashboard')}
              style={{
                background: 'none',
                border: 'none',
                color: '#6b8fa3',
                fontSize: 12,
                cursor: 'pointer',
                textDecoration: 'underline',
                textAlign: 'center',
              }}
            >
              Skip for now
            </button>
          </form>
        ) : (
          <div style={{ textAlign: 'center', color: '#ff6688', padding: 40, fontSize: 13 }}>
            Failed to load 2FA setup. Please try again.
          </div>
        )}
      </motion.div>
    </div>
  );
}

function StepCard({
  number,
  title,
  children,
}: {
  number: number;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div
      style={{
        background: 'rgba(0,10,30,0.6)',
        border: '1px solid rgba(0,212,255,0.12)',
        borderRadius: 10,
        padding: '16px 18px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <span
          style={{
            width: 22,
            height: 22,
            borderRadius: '50%',
            background: 'rgba(0,212,255,0.15)',
            border: '1px solid rgba(0,212,255,0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 11,
            fontWeight: 800,
            color: '#00d4ff',
            flexShrink: 0,
          }}
        >
          {number}
        </span>
        <span
          style={{
            fontSize: 12,
            fontWeight: 700,
            color: '#e0f4ff',
            letterSpacing: 1,
            textTransform: 'uppercase',
          }}
        >
          {title}
        </span>
      </div>
      {children}
    </div>
  );
}
