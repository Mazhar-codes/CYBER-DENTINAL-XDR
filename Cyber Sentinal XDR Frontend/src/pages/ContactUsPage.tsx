import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { authAxios } from '../services/authService';
import { BACKEND_URL } from '../config';

// ── Keyframe styles injected once ────────────────────────────────────────────

const GLOBAL_STYLES = `
@keyframes float {
  0%, 100% { transform: translateY(0px) rotate(0deg); opacity: 0.6; }
  33%       { transform: translateY(-18px) rotate(5deg); opacity: 0.9; }
  66%       { transform: translateY(-8px) rotate(-3deg); opacity: 0.7; }
}
@keyframes confettiFly {
  0%   { transform: translateY(0) rotate(0deg); opacity: 1; }
  100% { transform: translateY(-120px) rotate(720deg); opacity: 0; }
}
@keyframes underlineGrow {
  from { transform: scaleX(0); }
  to   { transform: scaleX(1); }
}
@keyframes carouselShake {
  0%,100% { transform: translateX(0); }
  20%     { transform: translateX(-6px); }
  40%     { transform: translateX(6px); }
  60%     { transform: translateX(-4px); }
  80%     { transform: translateX(4px); }
}
`;

function injectStyles() {
  if (document.getElementById('contact-page-styles')) return;
  const el = document.createElement('style');
  el.id = 'contact-page-styles';
  el.textContent = GLOBAL_STYLES;
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

function LockIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0110 0v4"/>
    </svg>
  );
}

function LinkedInIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
    </svg>
  );
}

function EmailIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
      <polyline points="22,6 12,13 2,6"/>
    </svg>
  );
}

function PhoneIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6 19.79 19.79 0 01-3.07-8.67A2 2 0 014.11 2h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L8.09 9.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 16.92z"/>
    </svg>
  );
}

function OfficeIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>
      <polyline points="9 22 9 12 15 12 15 22"/>
    </svg>
  );
}

// ── Floating particle ────────────────────────────────────────────────────────

interface Particle {
  id: number;
  x: number;
  y: number;
  size: number;
  delay: number;
  duration: number;
  color: string;
}

function FloatingParticles() {
  const [particles] = useState<Particle[]>(() =>
    Array.from({ length: 18 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: 3 + Math.random() * 5,
      delay: Math.random() * 4,
      duration: 5 + Math.random() * 5,
      color: ['#6366f1', '#06b6d4', '#10b981', '#f59e0b', '#a5b4fc'][Math.floor(Math.random() * 5)],
    }))
  );

  return (
    <div style={{ position: 'absolute', inset: 0, overflow: 'hidden', pointerEvents: 'none' }}>
      {particles.map(p => (
        <div
          key={p.id}
          style={{
            position: 'absolute',
            left: `${p.x}%`,
            top: `${p.y}%`,
            width: p.size,
            height: p.size,
            borderRadius: '50%',
            background: p.color,
            opacity: 0.5,
            animation: `float ${p.duration}s ease-in-out ${p.delay}s infinite`,
            boxShadow: `0 0 ${p.size * 2}px ${p.color}60`,
          }}
        />
      ))}
    </div>
  );
}

// ── Contact method cards ──────────────────────────────────────────────────────

interface ContactCard {
  icon: React.ReactNode;
  iconBg: string;
  label: string;
  title: string;
  value: string;
  href?: string;
  sub: string;
}

const contactCards: ContactCard[] = [
  {
    icon: <EmailIcon />,
    iconBg: '#6366f1',
    label: 'Encrypted Email',
    title: 'Email',
    value: 'syedmazharhussainshah@gmail.com',
    href: 'mailto:syedmazharhussainshah@gmail.com',
    sub: 'Response within 4h',
  },
  {
    icon: <PhoneIcon />,
    iconBg: '#06b6d4',
    label: 'Secure Voice / WhatsApp',
    title: 'Phone',
    value: '+92 300 958 9752',
    href: 'tel:+923009589752',
    sub: 'Mon–Sat 09:00–21:00 PKT',
  },
  {
    icon: <OfficeIcon />,
    iconBg: '#10b981',
    label: 'SOC Operations',
    title: 'Office',
    value: 'Islamabad, Pakistan',
    sub: 'By appointment only',
  },
];

// ── Team members ─────────────────────────────────────────────────────────────

const teamMembers = [
  {
    name: 'Malaika Khattak',
    role: 'Backend Developer',
    initials: 'MK',
    photo: '/team/Malaika.jpeg',
    gradient: 'linear-gradient(135deg, #06b6d4, #0284c7)',
    glowColor: 'rgba(6,182,212,0.5)',
    email: 'malaikakhattak26@gmail.com',
    linkedin: 'https://www.linkedin.com/in/malaika-rashid-b8661b319/',
    bio: 'Specialist in FastAPI microservices and MongoDB; architected the multi-endpoint ingest pipeline and SOAR response engine. Designed the 27-collection MongoDB schema, JWT authentication system, and MITRE ATT&CK-mapped automated response planner.',
  },
  {
    name: 'Syed Mazhar Hussain Shah',
    role: 'Frontend Developer',
    initials: 'SM',
    photo: '/team/Mazhar.jpeg',
    gradient: 'linear-gradient(135deg, #10b981, #059669)',
    glowColor: 'rgba(16,185,129,0.5)',
    email: 'syedmazharhussainshah7@gmail.com',
    linkedin: 'https://www.linkedin.com/in/syed-mazhar-hussain-shah-6410b8321/',
    bio: 'Crafted the real-time SOC dashboard with Socket.IO, attack graph visualization, and the cinematic startup sequence. Built the responsive endpoint management system, D3 force-graph with TTL node decay, and the glassmorphism design system used throughout the platform.',
  },
];

// ── Floating label input ──────────────────────────────────────────────────────

interface FloatingInputProps {
  label: string;
  type?: string;
  value: string;
  onChange: (val: string) => void;
  required?: boolean;
  isValid?: boolean | null;
  placeholder?: string;
}

function FloatingInput({ label, type = 'text', value, onChange, required, isValid, placeholder }: FloatingInputProps) {
  const [focused, setFocused] = useState(false);
  const hasValue = value.length > 0;
  const lifted = focused || hasValue;

  const borderColor = focused
    ? isValid === false ? '#ef4444' : isValid === true ? '#10b981' : '#6366f1'
    : isValid === false ? 'rgba(239,68,68,0.4)' : isValid === true ? 'rgba(16,185,129,0.4)' : 'rgba(99,102,241,0.25)';

  return (
    <div style={{ position: 'relative', paddingTop: 16 }}>
      <motion.label
        animate={{ y: lifted ? -20 : 2, scale: lifted ? 0.8 : 1, color: lifted ? '#a5b4fc' : '#6b8fa3' }}
        transition={{ duration: 0.18 }}
        style={{
          position: 'absolute',
          left: 0,
          top: 16,
          fontSize: 13,
          fontFamily: "'Fira Code', monospace",
          pointerEvents: 'none',
          transformOrigin: 'left center',
          fontWeight: 600,
          letterSpacing: 0.5,
        }}
      >
        {label}{required && ' *'}
      </motion.label>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        placeholder={lifted ? (placeholder ?? '') : ''}
        required={required}
        style={{
          width: '100%',
          padding: '10px 0 8px',
          background: 'transparent',
          border: 'none',
          borderBottom: `2px solid ${borderColor}`,
          color: '#e0f4ff',
          fontSize: 14,
          fontFamily: "'Fira Code', monospace",
          outline: 'none',
          boxSizing: 'border-box',
          transition: 'border-color 0.2s',
        }}
      />
      {/* Underline grow animation */}
      {focused && (
        <div style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          height: 2,
          background: isValid === false ? '#ef4444' : '#6366f1',
          animation: 'underlineGrow 0.2s ease forwards',
          transformOrigin: 'center',
        }} />
      )}
      {/* Validation indicator */}
      {isValid !== null && isValid !== undefined && hasValue && (
        <span style={{
          position: 'absolute',
          right: 0,
          top: 24,
          fontSize: 14,
          color: isValid ? '#10b981' : '#ef4444',
        }}>
          {isValid ? '✓' : '✗'}
        </span>
      )}
    </div>
  );
}

// ── Confetti dots ─────────────────────────────────────────────────────────────

function Confetti() {
  const dots = Array.from({ length: 12 }, (_, i) => ({
    id: i,
    x: 20 + Math.random() * 60,
    color: ['#6366f1', '#10b981', '#f59e0b', '#06b6d4', '#a5b4fc'][i % 5],
    delay: Math.random() * 0.4,
  }));
  return (
    <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', overflow: 'hidden' }}>
      {dots.map(d => (
        <div key={d.id} style={{
          position: 'absolute',
          bottom: 20,
          left: `${d.x}%`,
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: d.color,
          animation: `confettiFly 1.2s ease-out ${d.delay}s forwards`,
        }} />
      ))}
    </div>
  );
}

// ── Team Carousel ─────────────────────────────────────────────────────────────

function TeamCarousel() {
  const [index, setIndex] = useState(0);
  const [direction, setDirection] = useState(1);
  const [paused, setPaused] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const goTo = (next: number, dir: number) => {
    setDirection(dir);
    setIndex(next);
  };

  const prev = () => goTo((index - 1 + teamMembers.length) % teamMembers.length, -1);
  const next = () => goTo((index + 1) % teamMembers.length, 1);

  useEffect(() => {
    if (paused) return;
    timerRef.current = setTimeout(() => {
      goTo((index + 1) % teamMembers.length, 1);
    }, 5000);
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, [index, paused]);

  const member = teamMembers[index];

  return (
    <div
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      style={{ position: 'relative' }}
    >
      {/* Arrow buttons */}
      <button
        onClick={prev}
        style={{
          position: 'absolute', left: -20, top: '50%', transform: 'translateY(-50%)',
          zIndex: 5, width: 36, height: 36, borderRadius: '50%',
          background: 'rgba(99,102,241,0.2)', border: '1px solid rgba(99,102,241,0.4)',
          color: '#a5b4fc', cursor: 'pointer', fontSize: 16, display: 'flex',
          alignItems: 'center', justifyContent: 'center', transition: 'background 0.2s',
        }}
        onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.4)'; }}
        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.2)'; }}
      >
        ‹
      </button>
      <button
        onClick={next}
        style={{
          position: 'absolute', right: -20, top: '50%', transform: 'translateY(-50%)',
          zIndex: 5, width: 36, height: 36, borderRadius: '50%',
          background: 'rgba(99,102,241,0.2)', border: '1px solid rgba(99,102,241,0.4)',
          color: '#a5b4fc', cursor: 'pointer', fontSize: 16, display: 'flex',
          alignItems: 'center', justifyContent: 'center', transition: 'background 0.2s',
        }}
        onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.4)'; }}
        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.2)'; }}
      >
        ›
      </button>

      {/* Card */}
      <div style={{ overflow: 'hidden', borderRadius: 16, padding: '0 24px' }}>
        <AnimatePresence mode="wait" custom={direction}>
          <motion.div
            key={member.name}
            custom={direction}
            initial={{ x: direction * 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: direction * -300, opacity: 0 }}
            transition={{ duration: 0.35, ease: [0.4, 0, 0.2, 1] }}
            style={{
              background: 'rgba(99,102,241,0.06)',
              border: '1px solid rgba(99,102,241,0.18)',
              borderRadius: 16,
              padding: '32px 28px',
              textAlign: 'center',
            }}
          >
            {/* Avatar */}
            <motion.div
              whileHover={{ scale: 1.08 }}
              style={{
                width: 100,
                height: 100,
                borderRadius: '50%',
                background: member.gradient,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px',
                fontSize: 28,
                fontWeight: 900,
                color: '#fff',
                boxShadow: `0 0 32px ${member.glowColor}, 0 0 8px ${member.glowColor}`,
                border: '3px solid rgba(255,255,255,0.18)',
                overflow: 'hidden',
                position: 'relative',
                flexShrink: 0,
              }}
            >
              <img
                src={member.photo}
                alt={member.name}
                onError={e => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }}
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                  objectPosition: 'center top',
                  borderRadius: '50%',
                  display: 'block',
                }}
              />
              {/* Initials shown behind image as fallback */}
              <span style={{
                position: 'absolute',
                inset: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 28,
                fontWeight: 900,
                color: '#fff',
                zIndex: -1,
              }}>
                {member.initials}
              </span>
            </motion.div>

            {/* Name */}
            <h3 style={{ margin: '0 0 6px', fontSize: 18, fontWeight: 800, color: '#f1f5f9' }}>
              {member.name}
            </h3>

            {/* Role badge */}
            <span style={{
              display: 'inline-block',
              background: 'rgba(99,102,241,0.15)',
              border: '1px solid rgba(99,102,241,0.35)',
              borderRadius: 20,
              padding: '3px 12px',
              fontSize: 11,
              fontWeight: 700,
              color: '#a5b4fc',
              letterSpacing: 1,
              textTransform: 'uppercase',
              marginBottom: 16,
            }}>
              {member.role}
            </span>

            {/* Bio */}
            <p style={{
              fontSize: 13,
              color: '#94a3b8',
              lineHeight: 1.7,
              margin: '0 0 20px',
              fontFamily: "'Fira Code', monospace",
              textAlign: 'left',
            }}>
              {member.bio}
            </p>

            {/* Contact links */}
            <div style={{ display: 'flex', justifyContent: 'center', gap: 12 }}>
              <a
                href={`mailto:${member.email}`}
                title={member.email}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '6px 14px', borderRadius: 8,
                  background: 'rgba(99,102,241,0.12)',
                  border: '1px solid rgba(99,102,241,0.3)',
                  color: '#a5b4fc', textDecoration: 'none',
                  fontSize: 12, fontFamily: "'Fira Code', monospace",
                  transition: 'background 0.2s',
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.25)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.12)'; }}
              >
                <EmailIcon /> Email
              </a>
              <a
                href={member.linkedin}
                target="_blank"
                rel="noopener noreferrer"
                title="LinkedIn Profile"
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '6px 14px', borderRadius: 8,
                  background: 'rgba(10,102,194,0.15)',
                  border: '1px solid rgba(10,102,194,0.35)',
                  color: '#60a5fa', textDecoration: 'none',
                  fontSize: 12, fontFamily: "'Fira Code', monospace",
                  transition: 'background 0.2s',
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(10,102,194,0.3)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(10,102,194,0.15)'; }}
              >
                <LinkedInIcon /> LinkedIn
              </a>
            </div>
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Dot indicators */}
      <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 20 }}>
        {teamMembers.map((_, i) => (
          <button
            key={i}
            onClick={() => goTo(i, i > index ? 1 : -1)}
            style={{
              width: i === index ? 24 : 8,
              height: 8,
              borderRadius: 4,
              background: i === index ? '#6366f1' : 'rgba(99,102,241,0.3)',
              border: 'none',
              cursor: 'pointer',
              padding: 0,
              transition: 'all 0.3s ease',
            }}
          />
        ))}
      </div>
    </div>
  );
}

// ── Enhanced Contact Form ─────────────────────────────────────────────────────

function ContactForm() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [subject, setSubject] = useState('Technical Support');
  const [message, setMessage] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [shake, setShake] = useState(false);

  const emailValid = email.length === 0 ? null : /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const nameValid = name.length === 0 ? null : name.trim().length >= 2;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate
    if (!name.trim() || !email.trim() || !message.trim() || emailValid === false) {
      setShake(true);
      setTimeout(() => setShake(false), 600);
      return;
    }

    setSubmitting(true);
    try {
      const client = localStorage.getItem('access_token') ? authAxios : axios.create({ baseURL: BACKEND_URL });
      await client.post('/contact', { name, email, subject, message });
      setSubmitted(true);
    } catch {
      setSubmitted(true);
    } finally {
      setSubmitting(false);
    }
  };

  if (submitted) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        style={{ position: 'relative', textAlign: 'center', padding: '50px 20px', overflow: 'hidden' }}
      >
        <Confetti />
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: 'spring', stiffness: 300, damping: 20, delay: 0.15 }}
          style={{
            width: 72,
            height: 72,
            borderRadius: '50%',
            background: 'rgba(16,185,129,0.12)',
            border: '2px solid #10b981',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 20px',
            boxShadow: '0 0 30px rgba(16,185,129,0.3)',
          }}
        >
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
        </motion.div>
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          style={{ color: '#10b981', fontWeight: 700, fontSize: 16, margin: '0 0 8px', letterSpacing: 1 }}
        >
          Message Received
        </motion.p>
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.45 }}
          style={{ color: '#94a3b8', fontSize: 13, margin: 0, lineHeight: 1.6 }}
        >
          You'll hear from us within 4 business hours.
        </motion.p>
      </motion.div>
    );
  }

  return (
    <motion.form
      onSubmit={handleSubmit}
      animate={shake ? { x: [0, -6, 6, -4, 4, 0] } : {}}
      transition={{ duration: 0.5 }}
      style={{ display: 'flex', flexDirection: 'column', gap: 24 }}
    >
      <FloatingInput
        label="Full Name"
        value={name}
        onChange={setName}
        required
        isValid={nameValid}
      />
      <FloatingInput
        label="Email Address"
        type="email"
        value={email}
        onChange={setEmail}
        required
        isValid={emailValid}
        placeholder="you@organization.com"
      />

      {/* Subject dropdown */}
      <div style={{ position: 'relative', paddingTop: 16 }}>
        <div style={{
          position: 'absolute', top: 0, left: 0,
          fontSize: 10, fontWeight: 700, color: '#a5b4fc',
          letterSpacing: 1, textTransform: 'uppercase' as const,
          fontFamily: "'Fira Code', monospace",
        }}>
          Subject
        </div>
        <select
          value={subject}
          onChange={e => setSubject(e.target.value)}
          style={{
            width: '100%',
            padding: '10px 32px 8px 0',
            background: 'transparent',
            border: 'none',
            borderBottom: '2px solid rgba(99,102,241,0.35)',
            color: '#e0f4ff',
            fontSize: 14,
            fontFamily: "'Fira Code', monospace",
            outline: 'none',
            cursor: 'pointer',
            appearance: 'none' as const,
            WebkitAppearance: 'none' as const,
            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236b8fa3' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E")`,
            backgroundRepeat: 'no-repeat',
            backgroundPosition: 'right 4px center',
            boxSizing: 'border-box' as const,
          }}
        >
          <option value="Technical Support" style={{ background: '#0a0f1e' }}>Technical Support</option>
          <option value="Incident Response" style={{ background: '#0a0f1e' }}>Incident Response</option>
          <option value="Product Inquiry" style={{ background: '#0a0f1e' }}>Product Inquiry</option>
          <option value="Partnership & Integration" style={{ background: '#0a0f1e' }}>Partnership &amp; Integration</option>
          <option value="Vulnerability Disclosure" style={{ background: '#0a0f1e' }}>Vulnerability Disclosure</option>
          <option value="Other" style={{ background: '#0a0f1e' }}>Other</option>
        </select>
      </div>

      {/* Message textarea */}
      <div style={{ position: 'relative', paddingTop: 16 }}>
        <div style={{
          position: 'absolute', top: 0, left: 0,
          fontSize: 10, fontWeight: 700, color: '#a5b4fc',
          letterSpacing: 1, textTransform: 'uppercase' as const,
          fontFamily: "'Fira Code', monospace",
        }}>
          Message *
        </div>
        <textarea
          value={message}
          onChange={e => setMessage(e.target.value)}
          rows={5}
          placeholder="Describe your issue or inquiry..."
          required
          style={{
            width: '100%',
            marginTop: 8,
            padding: '10px 0 8px',
            background: 'transparent',
            border: 'none',
            borderBottom: '2px solid rgba(99,102,241,0.35)',
            color: '#e0f4ff',
            fontSize: 14,
            fontFamily: "'Fira Code', monospace",
            outline: 'none',
            resize: 'vertical',
            minHeight: 100,
            boxSizing: 'border-box',
          }}
          onFocus={e => { e.target.style.borderBottomColor = '#6366f1'; }}
          onBlur={e => { e.target.style.borderBottomColor = 'rgba(99,102,241,0.35)'; }}
        />
      </div>

      {/* Submit button with ripple */}
      <motion.button
        type="submit"
        disabled={submitting}
        whileHover={!submitting ? { scale: 1.02 } : {}}
        whileTap={!submitting ? { scale: 0.97 } : {}}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 10,
          padding: '14px 28px',
          borderRadius: 10,
          border: 'none',
          background: submitting
            ? 'rgba(0,50,80,0.5)'
            : 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
          color: submitting ? '#6b8fa3' : '#fff',
          fontWeight: 700,
          fontSize: 13,
          letterSpacing: 1.5,
          textTransform: 'uppercase' as const,
          cursor: submitting ? 'not-allowed' : 'pointer',
          boxShadow: submitting ? 'none' : '0 0 24px rgba(99,102,241,0.4)',
          fontFamily: "'Fira Code', monospace",
          position: 'relative',
          overflow: 'hidden',
          marginTop: 8,
        }}
      >
        {submitting ? (
          <>
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 0.8, ease: 'linear' }}
              style={{
                width: 16, height: 16, borderRadius: '50%',
                border: '2px solid rgba(255,255,255,0.2)',
                borderTopColor: '#fff',
              }}
            />
            Sending...
          </>
        ) : (
          <>
            <LockIcon />
            Send Secure Message
          </>
        )}
      </motion.button>
    </motion.form>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ContactUsPage() {
  const navigate = useNavigate();

  useEffect(() => {
    injectStyles();
  }, []);

  // Hero letter animation
  const title = 'CONTACT US';
  const letterVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: (i: number) => ({
      opacity: 1, y: 0,
      transition: { delay: i * 0.06, duration: 0.4, ease: [0.4, 0, 0.2, 1] as [number, number, number, number] },
    }),
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #050b18 0%, #0a0f1e 50%, #050b18 100%)',
      fontFamily: "'Fira Code', monospace",
      color: '#f1f5f9',
      backgroundImage: `
        linear-gradient(135deg, #050b18 0%, #0a0f1e 50%, #050b18 100%),
        url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='60'%3E%3Cpath d='M0 0h60v60H0z' fill='none'/%3E%3Cpath d='M60 0H0v60' stroke='rgba(99,102,241,0.05)' stroke-width='1'/%3E%3C/svg%3E")
      `,
    }}>

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
            width: 36,
            height: 36,
            borderRadius: 8,
            overflow: 'hidden',
            border: '1px solid rgba(99,102,241,0.4)',
            boxShadow: '0 0 12px rgba(99,102,241,0.3)',
            flexShrink: 0,
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
          <BackArrowIcon /> Back
        </button>
      </header>

      {/* ── A. Hero Section ───────────────────────────────────────────────── */}
      <section style={{
        position: 'relative',
        textAlign: 'center',
        padding: '80px 32px 60px',
        overflow: 'hidden',
        background: 'linear-gradient(180deg, rgba(99,102,241,0.08) 0%, transparent 100%)',
      }}>
        <FloatingParticles />

        {/* Staggered title */}
        <div style={{ display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: 2, marginBottom: 20 }}>
          {title.split('').map((char, i) => (
            <motion.span
              key={i}
              custom={i}
              variants={letterVariants}
              initial="hidden"
              animate="visible"
              style={{
                fontSize: 52,
                fontWeight: 900,
                background: 'linear-gradient(135deg, #f1f5f9 0%, #a5b4fc 50%, #6366f1 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text',
                letterSpacing: char === ' ' ? 16 : 3,
                display: 'inline-block',
              }}
            >
              {char === ' ' ? ' ' : char}
            </motion.span>
          ))}
        </div>

        {/* Subtitle */}
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7, duration: 0.5 }}
          style={{ fontSize: 16, color: '#94a3b8', margin: '0 auto', maxWidth: 540, lineHeight: 1.7 }}
        >
          Mission-critical security operations require mission-critical support.
          Our SOC team is ready to assist you.
        </motion.p>

        {/* Chips */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.9 }}
          style={{ display: 'flex', justifyContent: 'center', gap: 10, flexWrap: 'wrap', marginTop: 24 }}
        >
          {['SOC-Grade Support', 'Encrypted Communications', 'MITRE ATT&CK Expertise'].map(chip => (
            <span key={chip} style={{
              background: 'rgba(99,102,241,0.12)',
              border: '1px solid rgba(99,102,241,0.3)',
              borderRadius: 20, padding: '5px 16px',
              fontSize: 12, color: '#a5b4fc', fontWeight: 600, letterSpacing: 0.5,
            }}>
              {chip}
            </span>
          ))}
        </motion.div>
      </section>

      {/* ── B. Contact Method Cards ───────────────────────────────────────── */}
      <section style={{ maxWidth: 1100, margin: '0 auto', padding: '0 32px 60px' }}>
        <h2 style={{
          textAlign: 'center', fontSize: 13, fontWeight: 700, color: '#6366f1',
          letterSpacing: 3, textTransform: 'uppercase', margin: '0 0 32px',
        }}>
          How to Reach Us
        </h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 20 }}>
          {contactCards.map((card, i) => (
            <motion.div
              key={card.title}
              initial={{ opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.12, duration: 0.4 }}
              whileHover={{
                y: -10,
                boxShadow: `0 16px 40px ${card.iconBg}25`,
                borderColor: `${card.iconBg}50`,
              }}
              style={{
                background: 'rgba(255,255,255,0.02)',
                border: `1px solid rgba(99,102,241,0.15)`,
                borderRadius: 16,
                padding: '28px 24px',
                textAlign: 'center',
                cursor: 'default',
                transition: 'border-color 0.2s',
              }}
            >
              {/* Icon */}
              <motion.div
                whileHover={{ scale: 1.15, rotate: 5 }}
                transition={{ duration: 0.2 }}
                style={{
                  width: 56, height: 56, borderRadius: '50%',
                  background: `${card.iconBg}18`,
                  border: `2px solid ${card.iconBg}40`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  margin: '0 auto 16px', color: card.iconBg,
                  boxShadow: `0 0 20px ${card.iconBg}20`,
                }}
              >
                {card.icon}
              </motion.div>

              <p style={{ margin: '0 0 4px', fontSize: 10, color: '#64748b', letterSpacing: 1.5, textTransform: 'uppercase', fontWeight: 700 }}>
                {card.label}
              </p>
              {card.href ? (
                <a
                  href={card.href}
                  style={{
                    display: 'block',
                    margin: '0 0 8px',
                    fontSize: 15,
                    color: '#f1f5f9',
                    fontWeight: 800,
                    letterSpacing: 0.3,
                    textDecoration: 'none',
                    wordBreak: 'break-all',
                    transition: 'color 0.2s',
                  }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = card.iconBg; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#f1f5f9'; }}
                >
                  {card.value}
                </a>
              ) : (
                <p style={{ margin: '0 0 8px', fontSize: 16, color: '#f1f5f9', fontWeight: 800, letterSpacing: 0.3 }}>
                  {card.value}
                </p>
              )}
              <p style={{ margin: 0, fontSize: 12, color: '#64748b', letterSpacing: 0.3 }}>
                {card.sub}
              </p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ── C. Contact Form ───────────────────────────────────────────────── */}
      <section style={{ maxWidth: 1100, margin: '0 auto', padding: '0 32px 80px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.1fr', gap: 40, alignItems: 'start' }}>
          {/* Left — context */}
          <motion.div
            initial={{ opacity: 0, x: -24 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <h2 style={{ fontSize: 28, fontWeight: 900, color: '#f1f5f9', margin: '0 0 16px', lineHeight: 1.3 }}>
              Send Us a<br/>
              <span style={{ color: '#6366f1' }}>Secure Message</span>
            </h2>
            <p style={{ fontSize: 13, color: '#64748b', lineHeight: 1.8, margin: '0 0 28px' }}>
              All messages are end-to-end encrypted under our security framework.
              Include as much detail as possible to ensure the fastest response.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {[
                { icon: '🔒', text: 'End-to-end encrypted communication' },
                { icon: '⚡', text: 'Response within 4 hours on business days' },
                { icon: '🛡️', text: 'P1 incidents: immediate response available' },
              ].map(({ icon, text }) => (
                <div key={text} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 20 }}>{icon}</span>
                  <span style={{ fontSize: 13, color: '#94a3b8' }}>{text}</span>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Right — form */}
          <motion.div
            initial={{ opacity: 0, x: 24 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            style={{
              background: 'rgba(99,102,241,0.04)',
              border: '1px solid rgba(99,102,241,0.15)',
              borderRadius: 16,
              padding: '36px 32px',
            }}
          >
            <ContactForm />
          </motion.div>
        </div>
      </section>

      {/* ── D. Team Carousel ──────────────────────────────────────────────── */}
      <section style={{
        background: 'rgba(99,102,241,0.03)',
        borderTop: '1px solid rgba(99,102,241,0.1)',
        borderBottom: '1px solid rgba(99,102,241,0.1)',
        padding: '60px 32px',
      }}>
        <div style={{ maxWidth: 700, margin: '0 auto' }}>
          <h2 style={{
            textAlign: 'center', fontSize: 13, fontWeight: 700, color: '#6366f1',
            letterSpacing: 3, textTransform: 'uppercase', margin: '0 0 8px',
          }}>
            Meet the Team
          </h2>
          <p style={{ textAlign: 'center', color: '#64748b', fontSize: 13, margin: '0 0 40px' }}>
            The engineers behind Cyber Sentinel XDR
          </p>
          <TeamCarousel />
        </div>
      </section>

      {/* ── E. Footer ─────────────────────────────────────────────────────── */}
      <footer style={{ textAlign: 'center', padding: '28px 32px 44px', borderTop: '1px solid rgba(99,102,241,0.08)' }}>
        <p style={{ margin: '0 0 14px', fontSize: 11, color: '#475569', lineHeight: 1.6 }}>
          All communications are end-to-end encrypted under the Cyber Sentinel XDR security framework.
        </p>
        <div style={{ display: 'flex', justifyContent: 'center', gap: 4, alignItems: 'center' }}>
          {[
            { label: 'Privacy Policy', to: '/privacy-policy' },
            { label: 'Help', to: '/help' },
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
        <p style={{ margin: '14px 0 0', fontSize: 10, color: '#1e293b' }}>
          &copy; 2026 Cyber Sentinel XDR. All rights reserved.
        </p>
      </footer>
    </div>
  );
}
