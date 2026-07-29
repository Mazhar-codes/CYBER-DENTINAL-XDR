import React, { useRef, useEffect, useCallback, useState } from "react";
import {
  motion,
  AnimatePresence,
  useMotionValue,
  useSpring,
} from "framer-motion";
import {
  fadeInVariants,
  slideUpVariants,
  slideInLeftVariants,
  scaleInVariants,
  staggerContainerVariants,
  listItemVariants,
  slideUpVariants as pageVariants,
} from "./config";

// ── Reduced motion detection ─────────────────────────────────────────────────

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

// ── FadeIn ───────────────────────────────────────────────────────────────────

interface AnimProps {
  children: React.ReactNode;
  delay?: number;
  className?: string;
  style?: React.CSSProperties;
}

export function FadeIn({ children, delay, className, style }: AnimProps) {
  const reduced = prefersReducedMotion();
  return (
    <motion.div
      initial={reduced ? false : "hidden"}
      animate="visible"
      exit="exit"
      variants={fadeInVariants}
      transition={delay ? { delay } : undefined}
      className={className}
      style={style}
    >
      {children}
    </motion.div>
  );
}

// ── SlideUp ──────────────────────────────────────────────────────────────────

export function SlideUp({ children, delay, className, style }: AnimProps) {
  const reduced = prefersReducedMotion();
  return (
    <motion.div
      initial={reduced ? false : "hidden"}
      animate="visible"
      exit="exit"
      variants={slideUpVariants}
      transition={delay ? { delay } : undefined}
      className={className}
      style={style}
    >
      {children}
    </motion.div>
  );
}

// ── SlideInLeft ───────────────────────────────────────────────────────────────

export function SlideInLeft({ children, delay, className, style }: AnimProps) {
  const reduced = prefersReducedMotion();
  return (
    <motion.div
      initial={reduced ? false : "hidden"}
      animate="visible"
      exit="exit"
      variants={slideInLeftVariants}
      transition={delay ? { delay } : undefined}
      className={className}
      style={style}
    >
      {children}
    </motion.div>
  );
}

// ── ScaleIn ───────────────────────────────────────────────────────────────────

export function ScaleIn({ children, delay, className, style }: AnimProps) {
  const reduced = prefersReducedMotion();
  return (
    <motion.div
      initial={reduced ? false : "hidden"}
      animate="visible"
      exit="exit"
      variants={scaleInVariants}
      transition={delay ? { delay } : undefined}
      className={className}
      style={style}
    >
      {children}
    </motion.div>
  );
}

// ── StaggerContainer + StaggerItem ───────────────────────────────────────────

export function StaggerContainer({ children, className, style }: AnimProps) {
  const reduced = prefersReducedMotion();
  return (
    <motion.div
      initial={reduced ? false : "hidden"}
      animate="visible"
      variants={staggerContainerVariants}
      className={className}
      style={style}
    >
      {children}
    </motion.div>
  );
}

export function StaggerItem({ children, className, style }: AnimProps) {
  const reduced = prefersReducedMotion();
  return (
    <motion.div
      variants={reduced ? undefined : listItemVariants}
      className={className}
      style={style}
    >
      {children}
    </motion.div>
  );
}

// ── PageTransition ────────────────────────────────────────────────────────────

interface PageTransitionProps {
  children: React.ReactNode;
  pageKey: string;
  className?: string;
}

export function PageTransition({ children, pageKey, className }: PageTransitionProps) {
  const reduced = prefersReducedMotion();
  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={pageKey}
        initial={reduced ? false : "hidden"}
        animate="visible"
        exit="exit"
        variants={pageVariants}
        className={className}
        style={{ width: "100%", height: "100%" }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
}

// ── AnimatedNumber ────────────────────────────────────────────────────────────

interface AnimatedNumberProps {
  value: number;
  decimals?: number;
  suffix?: string;
  className?: string;
  style?: React.CSSProperties;
}

export function AnimatedNumber({
  value,
  decimals = 0,
  suffix = "",
  className,
  style,
}: AnimatedNumberProps) {
  const reduced = prefersReducedMotion();
  const motionVal = useMotionValue(reduced ? value : 0);
  const springVal = useSpring(motionVal, { stiffness: 100, damping: 20 });
  const [display, setDisplay] = useState(
    reduced ? value.toFixed(decimals) : "0"
  );

  useEffect(() => {
    motionVal.set(value);
  }, [value, motionVal]);

  useEffect(() => {
    const unsubscribe = springVal.on("change", (v: number) => {
      setDisplay(v.toFixed(decimals));
    });
    return unsubscribe;
  }, [springVal, decimals]);

  return (
    <span className={className} style={style}>
      {display}{suffix}
    </span>
  );
}

// ── SkeletonBlock ─────────────────────────────────────────────────────────────

interface SkeletonBlockProps {
  width?: string;
  height?: string;
  className?: string;
  rounded?: boolean;
  style?: React.CSSProperties;
}

export function SkeletonBlock({
  width = "100%",
  height = "20px",
  className,
  rounded = false,
  style,
}: SkeletonBlockProps) {
  return (
    <div
      className={`skeleton${className ? ` ${className}` : ""}`}
      style={{
        width,
        height,
        borderRadius: rounded ? 12 : 4,
        background: "rgba(99,102,241,0.15)",
        animation: "skeleton-pulse 1.6s ease-in-out infinite",
        ...style,
      }}
    />
  );
}

// ── RippleButton ──────────────────────────────────────────────────────────────

interface RippleButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger";
}

export function RippleButton({
  children,
  onClick,
  variant = "primary",
  className,
  style,
  ...rest
}: RippleButtonProps) {
  const btnRef = useRef<HTMLButtonElement>(null);

  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLButtonElement>) => {
      const btn = btnRef.current;
      if (!btn) return;

      const rect = btn.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const size = Math.max(rect.width, rect.height) * 2;

      const ripple = document.createElement("span");
      ripple.className = "ripple-circle";
      ripple.style.cssText = `
        left: ${x - size / 2}px;
        top: ${y - size / 2}px;
        width: ${size}px;
        height: ${size}px;
      `;
      btn.appendChild(ripple);

      // Remove after animation completes
      setTimeout(() => {
        if (btn.contains(ripple)) btn.removeChild(ripple);
      }, 600);

      if (onClick) onClick(e);
    },
    [onClick]
  );

  const variantStyle: React.CSSProperties =
    variant === "primary"
      ? { background: "linear-gradient(135deg, #3b82f6, #1d4ed8)", color: "#fff" }
      : variant === "danger"
      ? { background: "linear-gradient(135deg, #ef4444, #b91c1c)", color: "#fff" }
      : { background: "#1e293b", color: "#94a3b8" };

  return (
    <button
      ref={btnRef}
      onClick={handleClick}
      className={`ripple-btn xdr-btn${className ? ` ${className}` : ""}`}
      style={{ ...variantStyle, ...style }}
      {...rest}
    >
      {children}
    </button>
  );
}

// ── ReducedMotionWrapper ──────────────────────────────────────────────────────

interface ReducedMotionWrapperProps {
  children: React.ReactNode;
}

export function ReducedMotionWrapper({ children }: ReducedMotionWrapperProps) {
  const reduced = prefersReducedMotion();

  if (reduced) {
    // When reduced motion is requested, wrap in a plain div with AnimatePresence
    // in sync mode so there are no transitions at all.
    return (
      <AnimatePresence mode="sync">
        <motion.div initial={false}>
          {children}
        </motion.div>
      </AnimatePresence>
    );
  }

  return <>{children}</>;
}
