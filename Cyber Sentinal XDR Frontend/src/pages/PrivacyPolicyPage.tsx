import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';

// ── Print stylesheet injection ────────────────────────────────────────────────

const PRINT_STYLES = `
@media print {
  .no-print { display: none !important; }
  body { background: #fff !important; color: #000 !important; }
  a { color: #000 !important; }
}
`;

function injectPrintStyles() {
  if (document.getElementById('privacy-print-styles')) return;
  const el = document.createElement('style');
  el.id = 'privacy-print-styles';
  el.textContent = PRINT_STYLES;
  document.head.appendChild(el);
}

// ── Icon helpers ──────────────────────────────────────────────────────────────

function BackArrowIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="19" y1="12" x2="5" y2="12"/>
      <polyline points="12 19 5 12 12 5"/>
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  );
}

// ── Inline code block ─────────────────────────────────────────────────────────

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code style={{
      fontFamily: "'Fira Code', monospace",
      fontSize: 12,
      background: 'rgba(99,102,241,0.1)',
      border: '1px solid rgba(99,102,241,0.2)',
      borderRadius: 4,
      padding: '1px 6px',
      color: '#a5b4fc',
    }}>
      {children}
    </code>
  );
}

// ── Animated section heading ──────────────────────────────────────────────────

function SectionHeading({ children, id }: { children: React.ReactNode; id: string }) {
  return (
    <motion.div
      id={id}
      initial={{ opacity: 0, x: -20 }}
      whileInView={{ opacity: 1, x: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] }}
    >
      <h2 style={{
        fontSize: 17,
        fontWeight: 700,
        color: '#a5b4fc',
        margin: '0 0 12px',
        fontFamily: "'Fira Code', monospace",
        letterSpacing: 0.5,
        borderLeft: '3px solid #6366f1',
        paddingLeft: 12,
        scrollMarginTop: 80,
      }}>
        {children}
      </h2>
    </motion.div>
  );
}

function BodyText({ children }: { children: React.ReactNode }) {
  return (
    <p style={{
      fontSize: 14,
      color: '#94a3b8',
      lineHeight: 1.7,
      margin: '0 0 16px',
      fontFamily: "'Fira Code', monospace",
    }}>
      {children}
    </p>
  );
}

function BulletList({ items }: { items: React.ReactNode[] }) {
  return (
    <ul style={{ margin: '0 0 16px', paddingLeft: 20 }}>
      {items.map((item, i) => (
        <li key={i} style={{
          fontSize: 14,
          color: '#94a3b8',
          lineHeight: 1.7,
          marginBottom: 4,
          fontFamily: "'Fira Code', monospace",
        }}>
          {item}
        </li>
      ))}
    </ul>
  );
}

function Divider() {
  return <div style={{ borderTop: '1px solid rgba(99,102,241,0.1)', margin: '28px 0' }} />;
}

// ── TOC sections definition ───────────────────────────────────────────────────

const TOC_SECTIONS = [
  { id: 'section-1', label: '1. Introduction' },
  { id: 'section-2', label: '2. Information We Collect' },
  { id: 'section-3', label: '3. How We Use Information' },
  { id: 'section-4', label: '4. Data Retention' },
  { id: 'section-5', label: '5. Security Measures' },
  { id: 'section-6', label: '6. Your Rights' },
  { id: 'section-7', label: '7. Contact for Privacy Concerns' },
  { id: 'section-8', label: '8. Changes to This Policy' },
  { id: 'section-history', label: 'Document History' },
];

// ── Sticky TOC ────────────────────────────────────────────────────────────────

function TableOfContents({ activeId }: { activeId: string }) {
  return (
    <nav style={{
      position: 'sticky',
      top: 80,
      width: 200,
      flexShrink: 0,
      alignSelf: 'flex-start',
    }}
    className="no-print"
    >
      <p style={{
        fontSize: 10, fontWeight: 700, color: '#475569',
        letterSpacing: 2, textTransform: 'uppercase',
        margin: '0 0 12px', fontFamily: "'Fira Code', monospace",
      }}>
        Contents
      </p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {TOC_SECTIONS.map(s => (
          <button
            key={s.id}
            onClick={() => {
              const el = document.getElementById(s.id);
              if (el) el.scrollIntoView({ behavior: 'smooth' });
            }}
            style={{
              textAlign: 'left',
              background: activeId === s.id ? 'rgba(99,102,241,0.12)' : 'none',
              border: 'none',
              borderLeft: `2px solid ${activeId === s.id ? '#6366f1' : 'transparent'}`,
              padding: '5px 10px',
              cursor: 'pointer',
              fontSize: 11,
              color: activeId === s.id ? '#a5b4fc' : '#475569',
              fontFamily: "'Fira Code', monospace",
              transition: 'all 0.18s',
              borderRadius: '0 4px 4px 0',
              lineHeight: 1.4,
            }}
            onMouseEnter={e => {
              if (activeId !== s.id) {
                (e.currentTarget as HTMLElement).style.color = '#94a3b8';
                (e.currentTarget as HTMLElement).style.borderLeftColor = 'rgba(99,102,241,0.4)';
              }
            }}
            onMouseLeave={e => {
              if (activeId !== s.id) {
                (e.currentTarget as HTMLElement).style.color = '#475569';
                (e.currentTarget as HTMLElement).style.borderLeftColor = 'transparent';
              }
            }}
          >
            {s.label}
          </button>
        ))}
      </div>
    </nav>
  );
}

// ── Version timeline ──────────────────────────────────────────────────────────

function VersionTimeline() {
  const versions = [
    {
      version: 'v1.0',
      date: 'January 2026',
      label: 'Initial Release',
      changes: 'Initial Privacy Policy for Cyber Sentinel XDR v1.0. Covers endpoint telemetry, authentication data, security event logs, and MongoDB-hosted data practices.',
      color: '#6366f1',
    },
    {
      version: 'v1.1',
      date: 'March 2026',
      label: 'Endpoint Agent Update',
      changes: 'Added Section 2 clarification for multi-endpoint telemetry pipeline. Updated data retention timings to reflect new TTL index values. Added SOAR command audit logging disclosure.',
      color: '#06b6d4',
    },
    {
      version: 'v1.2',
      date: 'June 2026',
      label: 'RBAC & MFA Recovery',
      changes: 'Added RBAC data visibility clause. Documented MFA recovery request flow and admin-approval process. Added case notes collection to data types. Clarified PDF report retention policy.',
      color: '#10b981',
    },
  ];

  return (
    <div id="section-history" style={{ marginTop: 8, scrollMarginTop: 80 }}>
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        whileInView={{ opacity: 1, x: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.4 }}
      >
        <h2 style={{
          fontSize: 17, fontWeight: 700, color: '#a5b4fc', margin: '0 0 24px',
          fontFamily: "'Fira Code', monospace", letterSpacing: 0.5,
          borderLeft: '3px solid #6366f1', paddingLeft: 12,
        }}>
          Document History
        </h2>
      </motion.div>

      <div style={{ position: 'relative', paddingLeft: 24 }}>
        {/* Vertical line */}
        <div style={{
          position: 'absolute', left: 8, top: 0, bottom: 0,
          width: 2, background: 'rgba(99,102,241,0.2)',
        }} />

        {versions.map((v, i) => (
          <motion.div
            key={v.version}
            initial={{ opacity: 0, x: -16 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ delay: i * 0.1, duration: 0.4 }}
            style={{ position: 'relative', marginBottom: 28 }}
          >
            {/* Node dot */}
            <div style={{
              position: 'absolute', left: -20, top: 4,
              width: 14, height: 14, borderRadius: '50%',
              background: v.color,
              border: '2px solid #050b18',
              boxShadow: `0 0 10px ${v.color}60`,
            }} />

            <div style={{
              background: 'rgba(99,102,241,0.04)',
              border: '1px solid rgba(99,102,241,0.12)',
              borderRadius: 10, padding: '14px 18px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span style={{
                  fontSize: 12, fontWeight: 800, color: v.color,
                  fontFamily: "'Fira Code', monospace",
                  background: `${v.color}18`,
                  border: `1px solid ${v.color}40`,
                  borderRadius: 6, padding: '2px 8px',
                }}>
                  {v.version}
                </span>
                <span style={{ fontSize: 11, color: '#475569', fontFamily: "'Fira Code', monospace" }}>
                  {v.date}
                </span>
                <span style={{
                  fontSize: 10, fontWeight: 700, color: '#64748b',
                  letterSpacing: 0.5, textTransform: 'uppercase' as const,
                }}>
                  {v.label}
                </span>
              </div>
              <p style={{
                margin: 0, fontSize: 13, color: '#94a3b8',
                fontFamily: "'Fira Code', monospace", lineHeight: 1.6,
              }}>
                {v.changes}
              </p>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function PrivacyPolicyPage() {
  const navigate = useNavigate();
  const [activeId, setActiveId] = useState('section-1');
  const [isWide, setIsWide] = useState(window.innerWidth > 1024);

  useEffect(() => {
    injectPrintStyles();
    const handler = () => setIsWide(window.innerWidth > 1024);
    window.addEventListener('resize', handler);
    return () => window.removeEventListener('resize', handler);
  }, []);

  // IntersectionObserver for active TOC highlight
  useEffect(() => {
    const ids = TOC_SECTIONS.map(s => s.id);
    const observers: IntersectionObserver[] = [];

    ids.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      const obs = new IntersectionObserver(
        entries => {
          entries.forEach(entry => {
            if (entry.isIntersecting) setActiveId(id);
          });
        },
        { rootMargin: '-20% 0px -65% 0px', threshold: 0 }
      );
      obs.observe(el);
      observers.push(obs);
    });

    return () => observers.forEach(o => o.disconnect());
  }, []);

  return (
    <div style={{ minHeight: '100vh', background: '#050b18', fontFamily: "'Fira Code', monospace", color: '#f1f5f9' }}>

      {/* ── Sticky header ─────────────────────────────────────────────────── */}
      <header
        className="no-print"
        style={{
          position: 'sticky', top: 0, zIndex: 100,
          background: 'rgba(5,11,24,0.92)', backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          borderBottom: '1px solid rgba(99,102,241,0.15)',
          padding: '0 32px', display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', height: 60,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8, overflow: 'hidden', flexShrink: 0,
            border: '1px solid rgba(99,102,241,0.4)', boxShadow: '0 0 12px rgba(99,102,241,0.3)',
          }}>
            <img src="/logo.jpg" alt="Cyber Sentinel XDR" style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }} />
          </div>
          <span style={{ color: '#a5b4fc', fontWeight: 700, fontSize: 14, letterSpacing: 2, textTransform: 'uppercase' }}>
            CYBER SENTINEL XDR
          </span>
        </div>
        <button
          onClick={() => navigate(-1)}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.25)',
            borderRadius: 8, padding: '6px 14px', color: '#a5b4fc', fontSize: 12,
            cursor: 'pointer', fontFamily: "'Fira Code', monospace", letterSpacing: 0.5,
            transition: 'all 0.2s',
          }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.2)'; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.1)'; }}
        >
          <BackArrowIcon />
          Back
        </button>
      </header>

      {/* ── Outer layout: TOC + content ───────────────────────────────────── */}
      <div style={{
        maxWidth: isWide ? 1100 : 800,
        margin: '0 auto',
        padding: '48px 32px 80px',
        display: 'flex',
        gap: 40,
        alignItems: 'flex-start',
      }}>
        {/* Sticky TOC — desktop only */}
        {isWide && <TableOfContents activeId={activeId} />}

        {/* Main document body */}
        <main style={{ flex: 1, minWidth: 0 }}>

          {/* Title block */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            style={{ marginBottom: 32 }}
          >
            {/* Logo + title row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
              <div style={{
                width: 64, height: 64, borderRadius: 14, overflow: 'hidden', flexShrink: 0,
                border: '2px solid rgba(99,102,241,0.4)',
                boxShadow: '0 0 24px rgba(99,102,241,0.25)',
              }}>
                <img src="/logo.jpg" alt="Cyber Sentinel XDR" style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }} />
              </div>
              <div>
                <h1 style={{ fontSize: 36, fontWeight: 900, color: '#f1f5f9', margin: '0 0 4px', letterSpacing: 0.5 }}>
                  Privacy Policy
                </h1>
                <p style={{ fontSize: 13, color: '#64748b', margin: 0 }}>
                  Cyber Sentinel XDR Enterprise Security Platform
                </p>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
              <div style={{
                display: 'inline-flex', alignItems: 'center', gap: 8,
                background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.25)',
                borderRadius: 6, padding: '4px 12px',
              }}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#a5b4fc" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/>
                  <polyline points="12 6 12 12 16 14"/>
                </svg>
                <span style={{ color: '#a5b4fc', fontSize: 11, fontWeight: 600, letterSpacing: 1 }}>
                  Last updated: January 2026 · Version 1.2
                </span>
              </div>

              {/* PDF Download button */}
              <button
                onClick={() => window.print()}
                className="no-print"
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  padding: '5px 14px', borderRadius: 6,
                  background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)',
                  color: '#10b981', cursor: 'pointer', fontSize: 12,
                  fontFamily: "'Fira Code', monospace", fontWeight: 600,
                  transition: 'background 0.2s',
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(16,185,129,0.2)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(16,185,129,0.1)'; }}
              >
                <DownloadIcon /> Download PDF
              </button>
            </div>
          </motion.div>

          {/* ── Section 1 — Introduction ─────────────────────────────────── */}
          <div id="section-1" style={{ scrollMarginTop: 80 }}>
            <SectionHeading id="section-1-heading">1. Introduction</SectionHeading>
            <BodyText>
              Cyber Sentinel XDR ("the Platform") is an enterprise-grade Extended Detection and Response system.
              This Privacy Policy describes how we handle information collected through the Platform's operation,
              including endpoint telemetry, user authentication data, and security event logs. By deploying and
              using the Platform, you agree to the data handling practices described in this document.
            </BodyText>
          </div>

          <Divider />

          {/* ── Section 2 — Information We Collect ───────────────────────── */}
          <div id="section-2" style={{ scrollMarginTop: 80 }}>
            <SectionHeading id="section-2-heading">2. Information We Collect</SectionHeading>
            <BodyText>The Platform collects the following categories of information solely for security purposes:</BodyText>
            <BulletList items={[
              <>Endpoint telemetry: <Code>CPU usage</Code>, <Code>memory usage</Code>, <Code>network connections</Code>, and process lists — used for threat detection only, never for productivity monitoring</>,
              <>Authentication data: Email address, <Code>bcrypt-12</Code> hashed passwords (irreversible), TOTP secrets (encrypted at rest in MongoDB)</>,
              <>Security event logs: IP addresses, HTTP status codes, access timestamps, and access patterns — retained for audit compliance</>,
              'Analyst case notes and incident reports: stored exclusively in your self-hosted MongoDB instance',
              <>Device trust tokens: non-reversible hashed browser identifiers used to reduce MFA friction on trusted devices</>,
            ]} />
          </div>

          <Divider />

          {/* ── Section 3 — How We Use Information ───────────────────────── */}
          <div id="section-3" style={{ scrollMarginTop: 80 }}>
            <SectionHeading id="section-3-heading">3. How We Use Information</SectionHeading>
            <BulletList items={[
              'Threat detection and security alerting — primary and only purpose for telemetry data',
              <>Compliance audit trails — RBAC access logs, role changes, force logouts, and monitoring events</>,
              <>Incident response and forensic investigation — fusion alerts, SHAP explanations, and response plans</>,
              <>ML model inference — network, user behavior, system, and malware models process telemetry in-memory; no data leaves your deployment</>,
            ]} />
            <div style={{
              background: 'rgba(16,185,129,0.06)',
              border: '1px solid rgba(16,185,129,0.2)',
              borderRadius: 8, padding: '12px 16px', marginTop: 4,
            }}>
              <p style={{ margin: 0, fontSize: 13, color: '#10b981', fontFamily: "'Fira Code', monospace", lineHeight: 1.6 }}>
                We do NOT sell, share, or transmit your data to third parties. All data remains within your self-hosted infrastructure.
              </p>
            </div>
          </div>

          <Divider />

          {/* ── Section 4 — Data Retention ────────────────────────────────── */}
          <div id="section-4" style={{ scrollMarginTop: 80 }}>
            <SectionHeading id="section-4-heading">4. Data Retention</SectionHeading>
            <BodyText>The Platform uses MongoDB <Code>TTL</Code> (Time-To-Live) indexes to automatically expire old data:</BodyText>
            <BulletList items={[
              <><Code>endpoint_logs</Code>: 90-day rolling window (TTL index on <Code>timestamp</Code> field)</>,
              <><Code>fused_alerts</Code>: 30-day rolling window</>,
              <><Code>security_events</Code>: 90 days</>,
              <><Code>sysmon_alerts</Code>: 30-day rolling window</>,
              'Incident reports: Permanent until manually deleted by an administrator',
              <><Code>critical_alerts</Code>: Permanently retained in dedicated evidence store</>,
              <><Code>audit_logs</Code>: 90-day rolling window</>,
            ]} />
          </div>

          <Divider />

          {/* ── Section 5 — Security Measures ────────────────────────────── */}
          <div id="section-5" style={{ scrollMarginTop: 80 }}>
            <SectionHeading id="section-5-heading">5. Security Measures</SectionHeading>
            <BodyText>The Platform implements enterprise-grade security controls to protect all stored data:</BodyText>
            <BulletList items={[
              'All data stored in your self-hosted MongoDB instance — no cloud data transfer by default',
              <>TLS 1.3 in transit when configured with a reverse proxy (<Code>NGINX</Code>/<Code>Caddy</Code> recommended for production)</>,
              <>JWT access tokens expire in <Code>15 minutes</Code>; refresh tokens expire in <Code>7 days</Code></>,
              <><Code>bcrypt</Code> work-factor-12 password hashing — computationally infeasible to reverse</>,
              <>TOTP secrets stored encrypted at rest; FIPS 140-2 compliant cryptographic primitives</>,
              <>Sliding-window rate limiting: 5 login attempts per IP per 15-minute window</>,
              'Account lockout after 5 consecutive failed authentication attempts',
              <>All authentication events emit <Code>audit_event</Code> Socket.IO notifications and persist to <Code>audit_logs</Code></>,
            ]} />
          </div>

          <Divider />

          {/* ── Section 6 — Your Rights ───────────────────────────────────── */}
          <div id="section-6" style={{ scrollMarginTop: 80 }}>
            <SectionHeading id="section-6-heading">6. Your Rights</SectionHeading>
            <BulletList items={[
              'Access: View your account data, authentication history, and case notes via the Profile page',
              'Correction: Update your email, password, or analyst notes at any time through the Platform UI',
              <>Deletion: Administrators can permanently delete user accounts from the User Management panel (<Code>Settings → User Management</Code>)</>,
              'Export: Incident reports are downloadable as cryptographically signed PDF documents',
              'MFA recovery: Submit a recovery request if you lose access to your authenticator device',
            ]} />
          </div>

          <Divider />

          {/* ── Section 7 — Contact for Privacy Concerns ─────────────────── */}
          <div id="section-7" style={{ scrollMarginTop: 80 }}>
            <SectionHeading id="section-7-heading">7. Contact for Privacy Concerns</SectionHeading>
            <BodyText>
              For privacy-related inquiries, data access requests, or concerns about how your information is handled,
              please contact us directly. All privacy inquiries are responded to within 72 hours during business days.
            </BodyText>
            <div style={{
              background: 'rgba(99,102,241,0.06)',
              border: '1px solid rgba(99,102,241,0.15)',
              borderRadius: 8, padding: '14px 18px',
              display: 'flex', flexDirection: 'column', gap: 6,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#a5b4fc" strokeWidth="2">
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
                  <polyline points="22,6 12,13 2,6"/>
                </svg>
                <span style={{ fontSize: 13, color: '#94a3b8', fontFamily: "'Fira Code', monospace" }}>
                  Email:{' '}
                  <a
                    href="mailto:syedmazharhussainshah@gmail.com"
                    style={{ color: '#a5b4fc', textDecoration: 'none', transition: 'color 0.2s' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#c7d2fe'; }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#a5b4fc'; }}
                  >
                    syedmazharhussainshah@gmail.com
                  </a>
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#a5b4fc" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/>
                  <polyline points="12 6 12 12 16 14"/>
                </svg>
                <span style={{ fontSize: 13, color: '#64748b', fontFamily: "'Fira Code', monospace" }}>
                  Response SLA: 72 hours for privacy inquiries
                </span>
              </div>
            </div>
          </div>

          <Divider />

          {/* ── Section 8 — Changes to This Policy ───────────────────────── */}
          <div id="section-8" style={{ scrollMarginTop: 80 }}>
            <SectionHeading id="section-8-heading">8. Changes to This Policy</SectionHeading>
            <BodyText>
              We may update this Privacy Policy to reflect changes in the Platform's data handling practices or
              applicable regulations. Updates will be communicated through the Platform's release notes and
              the version badge below. Continued use of the Platform after a policy update constitutes acceptance
              of the revised terms.
            </BodyText>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              {[
                { label: 'Version', value: '1.2.0' },
                { label: 'Effective', value: 'January 2026' },
                { label: 'Last Revised', value: 'June 2026' },
              ].map(({ label, value }) => (
                <div key={label} style={{
                  background: 'rgba(99,102,241,0.08)',
                  border: '1px solid rgba(99,102,241,0.2)',
                  borderRadius: 6, padding: '6px 14px', fontSize: 11,
                  fontFamily: "'Fira Code', monospace",
                }}>
                  <span style={{ color: '#64748b' }}>{label}: </span>
                  <span style={{ color: '#a5b4fc', fontWeight: 700 }}>{value}</span>
                </div>
              ))}
            </div>
          </div>

          <Divider />

          {/* ── Document History / Version Timeline ───────────────────────── */}
          <VersionTimeline />

          {/* ── Footer nav ────────────────────────────────────────────────── */}
          <div style={{ marginTop: 48, textAlign: 'center' }}>
            <div style={{ display: 'flex', justifyContent: 'center', gap: 4, alignItems: 'center' }}>
              {[
                { label: 'Help', to: '/help' },
                { label: 'Contact Us', to: '/contact-us' },
                { label: 'Back to Login', to: '/login' },
              ].map(({ label, to }, i) => (
                <React.Fragment key={label}>
                  {i > 0 && <span style={{ color: '#1e293b', fontSize: 11, margin: '0 4px' }}>·</span>}
                  <Link
                    to={to}
                    style={{ color: '#475569', fontSize: 11, textDecoration: 'none', fontFamily: "'Fira Code', monospace", transition: 'color 0.2s' }}
                    onMouseEnter={e => ((e.currentTarget as HTMLElement).style.color = '#94a3b8')}
                    onMouseLeave={e => ((e.currentTarget as HTMLElement).style.color = '#475569')}
                  >
                    {label}
                  </Link>
                </React.Fragment>
              ))}
            </div>
            <p style={{ margin: '12px 0 0', fontSize: 11, color: '#1e293b', fontFamily: "'Fira Code', monospace" }}>
              &copy; 2026 Cyber Sentinel XDR. All rights reserved. CONFIDENTIAL — Enterprise use only.
            </p>
          </div>
        </main>
      </div>
    </div>
  );
}
