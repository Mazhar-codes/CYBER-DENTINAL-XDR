import React, { useState, useRef, useCallback, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { FadeIn, SlideUp } from '../animations/components';

// ── Types ─────────────────────────────────────────────────────────────────────

interface FAQItem {
  question: string;
  answer: string;
  category: string;
}

interface FAQSection {
  title: string;
  icon: React.ReactNode;
  category: string;
  items: FAQItem[];
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

function SearchIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#6b8fa3" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/>
      <line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <motion.svg
      animate={{ rotate: open ? 180 : 0 }}
      transition={{ duration: 0.22 }}
      width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
      style={{ flexShrink: 0 }}
    >
      <polyline points="6 9 12 15 18 9"/>
    </motion.svg>
  );
}

function StartIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>
  );
}

function RadarIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <circle cx="12" cy="12" r="6"/>
      <circle cx="12" cy="12" r="2"/>
    </svg>
  );
}

function ShieldSmIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  );
}

function KeyIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18"/>
      <line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  );
}

function ChatIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
    </svg>
  );
}

// ── FAQ data ──────────────────────────────────────────────────────────────────

const faqSections: FAQSection[] = [
  {
    title: 'Getting Started',
    icon: <StartIcon />,
    category: 'getting-started',
    items: [
      {
        question: 'How do I start monitoring?',
        answer: "Click 'Start Monitoring' in the top bar after logging in. Ensure MongoDB and the backend server are running. The button will be active once the system is ready.",
        category: 'getting-started',
      },
      {
        question: 'What are the system requirements?',
        answer: 'Windows 10/11, Python 3.10+, Node.js 18+, MongoDB 6.0+, 8GB RAM minimum for ML models. 16GB RAM is recommended for running all four detection models concurrently.',
        category: 'getting-started',
      },
      {
        question: 'How do I add endpoints?',
        answer: 'Deploy the endpoint_agent package on each monitored host. Set XDR_BACKEND_URL and XDR_API_KEY in the .env file on each endpoint, then run agent.py. The endpoint will appear in the Endpoints view within 30 seconds.',
        category: 'getting-started',
      },
    ],
  },
  {
    title: 'Threat Detection',
    icon: <RadarIcon />,
    category: 'threat-detection',
    items: [
      {
        question: 'What models power the detection?',
        answer: 'Four AI models: RandomForest (network — CIC-IDS2017, 99.6% accuracy), One-Class SVM (user behavior — CERT Insider Threat r4.2), LSTM + Behavioral detector (system telemetry — dual-path: LSTM Autoencoder + Process Behavior classifier), and LightGBM (malware — EMBER 2018, AUC 0.9803). All outputs are fused into a single threat score.',
        category: 'threat-detection',
      },
      {
        question: 'What is the Fusion Score?',
        answer: 'A weighted combination of all detection model outputs scaled 0.0–1.0. Weights: Network 35%, Malware 20%, User 30%, System 15%. HIGH severity is triggered at ≥ 0.70 and CRITICAL at ≥ 0.85.',
        category: 'threat-detection',
      },
      {
        question: 'Why is SHAP shown in alerts?',
        answer: "SHAP (SHapley Additive exPlanations) shows which features contributed most to a detection decision, enabling analyst review and reducing false positives. Admin users see full feature values; analysts see summarized charts; viewers see plain-text summaries.",
        category: 'threat-detection',
      },
    ],
  },
  {
    title: 'Response & Remediation',
    icon: <ShieldSmIcon />,
    category: 'response',
    items: [
      {
        question: 'What SOAR actions are available?',
        answer: 'Nine actions: isolate_host (disables NIC), block_ip (netsh firewall rule), unblock_ip, kill_process (by PID or name), quarantine_file (moves to secure quarantine folder), lock_account (net user /active:no), scan_filesystem, monitor_persistence (registry + scheduled tasks), and unisolate_host.',
        category: 'response',
      },
      {
        question: 'Can responses be automated?',
        answer: "Yes. Enable Auto-Response in Settings → Detection. CRITICAL severity events trigger automated response plans including SOAR command execution and PDF incident report generation. Auto-response can be paused at any time.",
        category: 'response',
      },
      {
        question: 'How do I download an incident report?',
        answer: "Open the Endpoints view, find the incident in the Incident Reports section, and click Download PDF. Reports are ReportLab-generated 5-section documents: incident summary, attack timeline, SHAP explanation, response actions, and analyst certification.",
        category: 'response',
      },
    ],
  },
  {
    title: 'Authentication',
    icon: <KeyIcon />,
    category: 'authentication',
    items: [
      {
        question: 'Why is 2FA required?',
        answer: 'Two-factor authentication is mandatory for all users to meet zero-trust architecture requirements. The platform uses TOTP (RFC 6238) compatible with Google Authenticator, Authy, and any standard OTP app.',
        category: 'authentication',
      },
      {
        question: 'How do I recover access if I lose my MFA device?',
        answer: "Use a backup code from your profile page — you were given 8 one-time codes during initial setup. If you have no backup codes, submit an MFA Recovery Request from the login page. Admins approve recovery requests from the Profile admin panel.",
        category: 'authentication',
      },
      {
        question: 'What do backup codes do?',
        answer: 'Backup codes are one-time-use codes that bypass TOTP for emergency access. Each code can only be used once. Store them in a password manager or printed in a secure physical location. New codes can be generated from your Profile page.',
        category: 'authentication',
      },
    ],
  },
];

// Flatten all items for autocomplete
const allFAQItems = faqSections.flatMap(s => s.items.map(item => ({ ...item, sectionTitle: s.title })));

// ── Highlight matching text ───────────────────────────────────────────────────

function HighlightText({ text, query }: { text: string; query: string }) {
  if (!query) return <>{text}</>;
  const idx = text.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return <>{text}</>;
  return (
    <>
      {text.slice(0, idx)}
      <mark style={{ background: 'rgba(99,102,241,0.35)', color: '#a5b4fc', borderRadius: 2, padding: '0 1px' }}>
        {text.slice(idx, idx + query.length)}
      </mark>
      {text.slice(idx + query.length)}
    </>
  );
}

// ── FAQItem component ─────────────────────────────────────────────────────────

function FAQItemRow({ item, isOpen, onToggle, query }: {
  item: FAQItem; isOpen: boolean; onToggle: () => void; query?: string;
}) {
  return (
    <div style={{ borderBottom: '1px solid rgba(99,102,241,0.1)', overflow: 'hidden' }}>
      <button
        onClick={onToggle}
        style={{
          width: '100%', display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', gap: 16, padding: '16px 0',
          background: 'none', border: 'none', cursor: 'pointer',
          textAlign: 'left', fontFamily: "'Fira Code', monospace",
        }}
      >
        <span style={{
          fontSize: 13, fontWeight: isOpen ? 700 : 600,
          color: isOpen ? '#a5b4fc' : '#cbd5e1',
          lineHeight: 1.4, transition: 'color 0.2s',
        }}>
          {query ? <HighlightText text={item.question} query={query} /> : item.question}
        </span>
        <span style={{ color: isOpen ? '#6366f1' : '#475569', transition: 'color 0.2s' }}>
          <ChevronIcon open={isOpen} />
        </span>
      </button>

      <AnimatePresence initial={false}>
        {isOpen && (
          <motion.div
            key="answer"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: 'easeInOut' }}
            style={{ overflow: 'hidden' }}
          >
            <p style={{
              margin: '0 0 16px', fontSize: 13, color: '#94a3b8',
              lineHeight: 1.7, fontFamily: "'Fira Code', monospace", paddingRight: 32,
            }}>
              {item.answer}
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Floating chat widget ──────────────────────────────────────────────────────

function ChatWidget() {
  const [open, setOpen] = useState(false);

  return (
    <div style={{ position: 'fixed', bottom: 28, right: 28, zIndex: 500 }}>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, scale: 0.8, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.8, y: 20 }}
            transition={{ duration: 0.22 }}
            style={{
              position: 'absolute', bottom: 60, right: 0,
              width: 280, borderRadius: 14,
              background: 'rgba(10,15,30,0.98)',
              border: '1px solid rgba(99,102,241,0.3)',
              boxShadow: '0 16px 48px rgba(0,0,0,0.5)',
              overflow: 'hidden',
            }}
          >
            {/* Header */}
            <div style={{
              padding: '14px 16px',
              background: 'linear-gradient(135deg, rgba(99,102,241,0.25), rgba(99,102,241,0.1))',
              borderBottom: '1px solid rgba(99,102,241,0.15)',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{
                  width: 8, height: 8, borderRadius: '50%',
                  background: '#10b981', boxShadow: '0 0 6px #10b981',
                }} />
                <span style={{ color: '#a5b4fc', fontWeight: 700, fontSize: 12 }}>XDR Support</span>
              </div>
              <button
                onClick={() => setOpen(false)}
                style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', padding: 0 }}
              >
                <CloseIcon />
              </button>
            </div>

            {/* Body */}
            <div style={{ padding: '16px' }}>
              <p style={{
                margin: '0 0 16px', fontSize: 13, color: '#94a3b8',
                lineHeight: 1.7, fontFamily: "'Fira Code', monospace",
              }}>
                Hi! Need help? Send us a message via the Contact Us page or reach us directly via email.
              </p>
              <Link
                to="/contact-us"
                onClick={() => setOpen(false)}
                style={{
                  display: 'block', textAlign: 'center',
                  padding: '10px 16px', borderRadius: 8,
                  background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
                  color: '#fff', textDecoration: 'none', fontSize: 12,
                  fontWeight: 700, letterSpacing: 0.5, fontFamily: "'Fira Code', monospace",
                  marginBottom: 10,
                }}
              >
                Open Contact Form
              </Link>
              <a
                href="mailto:syedmazharhussainshah@gmail.com"
                style={{
                  display: 'block', textAlign: 'center',
                  padding: '8px 16px', borderRadius: 8,
                  background: 'rgba(99,102,241,0.1)',
                  border: '1px solid rgba(99,102,241,0.25)',
                  color: '#a5b4fc', textDecoration: 'none', fontSize: 11,
                  fontFamily: "'Fira Code', monospace",
                }}
              >
                syedmazharhussainshah@gmail.com
              </a>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Trigger button */}
      <motion.button
        onClick={() => setOpen(o => !o)}
        whileHover={{ scale: 1.08 }}
        whileTap={{ scale: 0.94 }}
        style={{
          width: 52, height: 52, borderRadius: '50%',
          background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
          border: 'none', cursor: 'pointer',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: '#fff', boxShadow: '0 4px 20px rgba(99,102,241,0.5)',
          position: 'relative',
        }}
      >
        <AnimatePresence mode="wait">
          {open ? (
            <motion.div key="close" initial={{ rotate: -90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: 90, opacity: 0 }} transition={{ duration: 0.15 }}>
              <CloseIcon />
            </motion.div>
          ) : (
            <motion.div key="chat" initial={{ rotate: 90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }} exit={{ rotate: -90, opacity: 0 }} transition={{ duration: 0.15 }}>
              <ChatIcon />
            </motion.div>
          )}
        </AnimatePresence>

        {/* Pulsing ring */}
        {!open && (
          <motion.div
            animate={{ scale: [1, 1.6], opacity: [0.6, 0] }}
            transition={{ repeat: Infinity, duration: 1.8, ease: 'easeOut' }}
            style={{
              position: 'absolute', inset: -4,
              borderRadius: '50%',
              border: '2px solid #6366f1',
              pointerEvents: 'none',
            }}
          />
        )}
      </motion.button>
    </div>
  );
}

// ── Category tabs ─────────────────────────────────────────────────────────────

const TABS = [
  { id: 'all', label: 'All' },
  { id: 'getting-started', label: 'Getting Started' },
  { id: 'threat-detection', label: 'Threat Detection' },
  { id: 'response', label: 'Response & Remediation' },
  { id: 'authentication', label: 'Authentication' },
];

// ── Main component ────────────────────────────────────────────────────────────

export default function HelpPage() {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [openItems, setOpenItems] = useState<Record<string, boolean>>({});
  const [activeTab, setActiveTab] = useState('all');
  const [suggestions, setSuggestions] = useState<typeof allFAQItems>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);
  const sectionRefs = useRef<Record<string, HTMLDivElement | null>>({});

  const toggleItem = (key: string) => {
    setOpenItems(prev => ({ ...prev, [key]: !prev[key] }));
  };

  // Autocomplete logic
  useEffect(() => {
    if (query.length >= 2) {
      const matches = allFAQItems
        .filter(item =>
          item.question.toLowerCase().includes(query.toLowerCase()) ||
          item.answer.toLowerCase().includes(query.toLowerCase())
        )
        .slice(0, 5);
      setSuggestions(matches);
      setShowSuggestions(matches.length > 0);
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
    }
  }, [query]);

  // Close suggestions on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const handleSuggestionClick = useCallback((item: typeof allFAQItems[0]) => {
    setQuery('');
    setShowSuggestions(false);
    setActiveTab('all');
    const key = `${item.sectionTitle}__${item.question}`;
    setOpenItems(prev => ({ ...prev, [key]: true }));
    // Scroll to section
    setTimeout(() => {
      const el = sectionRefs.current[item.sectionTitle];
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
  }, []);

  // Filter by tab and search query
  const filteredSections = faqSections
    .filter(section => activeTab === 'all' || section.category === activeTab)
    .map(section => ({
      ...section,
      items: section.items.filter(
        item =>
          !query ||
          item.question.toLowerCase().includes(query.toLowerCase()) ||
          item.answer.toLowerCase().includes(query.toLowerCase())
      ),
    }))
    .filter(section => section.items.length > 0);

  return (
    <div style={{ minHeight: '100vh', background: '#050b18', fontFamily: "'Fira Code', monospace", color: '#f1f5f9' }}>

      {/* ── Sticky header ─────────────────────────────────────────────────── */}
      <header style={{
        position: 'sticky', top: 0, zIndex: 100,
        background: 'rgba(5,11,24,0.92)', backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(99,102,241,0.15)',
        padding: '0 32px', display: 'flex', alignItems: 'center',
        justifyContent: 'space-between', height: 60,
      }}>
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

      {/* ── Hero / Search section ──────────────────────────────────────────── */}
      <section style={{ textAlign: 'center', padding: '60px 32px 32px' }}>
        <FadeIn>
          <h1 style={{ fontSize: 36, fontWeight: 900, color: '#f1f5f9', margin: '0 0 10px', letterSpacing: 1 }}>
            How can we help?
          </h1>
          <p style={{ fontSize: 14, color: '#64748b', margin: '0 0 28px' }}>
            Search the knowledge base or browse sections below.
          </p>

          {/* Search bar with autocomplete */}
          <div ref={searchRef} style={{ position: 'relative', maxWidth: 520, margin: '0 auto' }}>
            <div style={{
              position: 'absolute', left: 14, top: '50%',
              transform: 'translateY(-50%)', pointerEvents: 'none',
            }}>
              <SearchIcon />
            </div>
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onFocus={() => { if (suggestions.length > 0) setShowSuggestions(true); }}
              placeholder="Search questions..."
              style={{
                width: '100%', padding: '13px 14px 13px 44px',
                background: 'rgba(0,10,25,0.8)', border: '1px solid rgba(99,102,241,0.25)',
                borderRadius: showSuggestions ? '10px 10px 0 0' : 10,
                color: '#e0f4ff', fontSize: 14, fontFamily: "'Fira Code', monospace",
                outline: 'none', boxSizing: 'border-box',
                transition: 'border-color 0.2s, box-shadow 0.2s',
              }}
              onKeyDown={e => { if (e.key === 'Escape') { setShowSuggestions(false); setQuery(''); } }}
            />

            {/* Autocomplete dropdown */}
            <AnimatePresence>
              {showSuggestions && (
                <motion.div
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.18 }}
                  style={{
                    position: 'absolute', left: 0, right: 0, zIndex: 50,
                    background: 'rgba(5,11,24,0.98)',
                    border: '1px solid rgba(99,102,241,0.3)',
                    borderTop: 'none',
                    borderRadius: '0 0 10px 10px',
                    overflow: 'hidden',
                    boxShadow: '0 12px 32px rgba(0,0,0,0.4)',
                  }}
                >
                  {suggestions.map((item, i) => (
                    <button
                      key={i}
                      onMouseDown={() => handleSuggestionClick(item)}
                      style={{
                        width: '100%', display: 'block', textAlign: 'left',
                        padding: '11px 16px', background: 'none', border: 'none',
                        cursor: 'pointer', borderBottom: i < suggestions.length - 1 ? '1px solid rgba(99,102,241,0.08)' : 'none',
                        transition: 'background 0.15s',
                        fontFamily: "'Fira Code', monospace",
                      }}
                      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.1)'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'none'; }}
                    >
                      <div style={{ fontSize: 12, color: '#a5b4fc', marginBottom: 2 }}>
                        <HighlightText text={item.question} query={query} />
                      </div>
                      <div style={{ fontSize: 10, color: '#475569' }}>
                        {item.sectionTitle}
                      </div>
                    </button>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </FadeIn>
      </section>

      {/* ── Category tabs ──────────────────────────────────────────────────── */}
      <div style={{ maxWidth: 760, margin: '0 auto', padding: '0 32px 24px' }}>
        <div style={{
          display: 'flex', gap: 4, borderBottom: '1px solid rgba(99,102,241,0.12)',
          overflowX: 'auto', paddingBottom: 0,
        }}>
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                position: 'relative',
                padding: '10px 16px',
                background: 'none', border: 'none', cursor: 'pointer',
                color: activeTab === tab.id ? '#a5b4fc' : '#475569',
                fontFamily: "'Fira Code', monospace",
                fontSize: 12, fontWeight: activeTab === tab.id ? 700 : 500,
                letterSpacing: 0.5, whiteSpace: 'nowrap',
                transition: 'color 0.2s',
                flexShrink: 0,
              }}
            >
              {tab.label}
              {activeTab === tab.id && (
                <motion.div
                  layoutId="tab-underline"
                  style={{
                    position: 'absolute', bottom: 0, left: 0, right: 0,
                    height: 2, background: '#6366f1', borderRadius: 1,
                  }}
                  transition={{ type: 'spring', stiffness: 400, damping: 35 }}
                />
              )}
            </button>
          ))}
        </div>
      </div>

      {/* ── FAQ accordion sections ─────────────────────────────────────────── */}
      <main style={{ maxWidth: 760, margin: '0 auto', padding: '0 32px 32px' }}>
        {filteredSections.length === 0 ? (
          <FadeIn>
            <div style={{ textAlign: 'center', padding: '60px 0', color: '#475569', fontSize: 13 }}>
              No results found for "{query}". Try different keywords or{' '}
              <Link to="/contact-us" style={{ color: '#6366f1', textDecoration: 'none' }}>contact support</Link>.
            </div>
          </FadeIn>
        ) : (
          filteredSections.map((section, sIdx) => (
            <div
              key={section.title}
              ref={el => { sectionRefs.current[section.title] = el; }}
            >
              <SlideUp delay={sIdx * 0.08}>
                <div style={{
                  background: 'rgba(99,102,241,0.04)',
                  border: '1px solid rgba(99,102,241,0.12)',
                  borderRadius: 12, padding: '20px 24px', marginBottom: 20,
                }}>
                  {/* Section header */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                    {section.icon}
                    <h2 style={{
                      margin: 0, fontSize: 14, fontWeight: 700,
                      color: '#a5b4fc', letterSpacing: 1.5, textTransform: 'uppercase',
                    }}>
                      {section.title}
                    </h2>
                  </div>

                  {/* FAQ items */}
                  {section.items.map((item) => {
                    const key = `${section.title}__${item.question}`;
                    return (
                      <FAQItemRow
                        key={key}
                        item={item}
                        isOpen={!!openItems[key]}
                        onToggle={() => toggleItem(key)}
                        query={query}
                      />
                    );
                  })}
                </div>
              </SlideUp>
            </div>
          ))
        )}

        {/* ── Still need help? CTA ──────────────────────────────────────── */}
        <FadeIn delay={0.35}>
          <div style={{
            textAlign: 'center',
            background: 'rgba(99,102,241,0.06)',
            border: '1px solid rgba(99,102,241,0.15)',
            borderRadius: 12, padding: '32px 24px', marginTop: 32,
          }}>
            <p style={{ margin: '0 0 16px', fontSize: 14, color: '#94a3b8', lineHeight: 1.6 }}>
              Still need help? Our security team is available during business hours.
            </p>
            <Link
              to="/contact-us"
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 8,
                padding: '11px 24px', borderRadius: 8,
                background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
                color: '#fff', fontWeight: 700, fontSize: 13, letterSpacing: 1.5,
                textTransform: 'uppercase', textDecoration: 'none',
                boxShadow: '0 0 20px rgba(99,102,241,0.3)',
                fontFamily: "'Fira Code', monospace", transition: 'opacity 0.2s',
              }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.opacity = '0.88'; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.opacity = '1'; }}
            >
              Contact our security team directly
            </Link>
          </div>
        </FadeIn>
      </main>

      {/* ── Footer ────────────────────────────────────────────────────────── */}
      <footer style={{ textAlign: 'center', padding: '20px 32px 60px', borderTop: '1px solid rgba(99,102,241,0.1)' }}>
        <div style={{ display: 'flex', justifyContent: 'center', gap: 4, alignItems: 'center' }}>
          {[
            { label: 'Privacy Policy', to: '/privacy-policy' },
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
      </footer>

      {/* ── Floating chat widget ───────────────────────────────────────────── */}
      <ChatWidget />
    </div>
  );
}
