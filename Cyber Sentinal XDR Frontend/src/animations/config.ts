// Central animation timing + easing constants used across the entire dashboard
export const DURATION = {
  fast: 0.15,
  normal: 0.3,
  slow: 0.5,
  page: 0.4,
} as const;

export const EASE = {
  out: [0.0, 0.0, 0.2, 1],
  in: [0.4, 0.0, 1, 1],
  inOut: [0.4, 0.0, 0.2, 1],
  spring: { type: "spring", stiffness: 300, damping: 30 },
  springGentle: { type: "spring", stiffness: 200, damping: 25 },
} as const;

export const STAGGER = {
  fast: 0.05,
  normal: 0.08,
  slow: 0.12,
} as const;

// Framer Motion variants for reuse
export const fadeInVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: DURATION.normal, ease: EASE.out } },
  exit: { opacity: 0, transition: { duration: DURATION.fast, ease: EASE.in } },
};

export const slideUpVariants = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { duration: DURATION.normal, ease: EASE.out } },
  exit: { opacity: 0, y: -8, transition: { duration: DURATION.fast } },
};

export const slideInLeftVariants = {
  hidden: { opacity: 0, x: -20 },
  visible: { opacity: 1, x: 0, transition: { duration: DURATION.normal, ease: EASE.out } },
  exit: { opacity: 0, x: -20, transition: { duration: DURATION.fast } },
};

export const scaleInVariants = {
  hidden: { opacity: 0, scale: 0.95 },
  visible: { opacity: 1, scale: 1, transition: { duration: DURATION.normal, ease: EASE.out } },
  exit: { opacity: 0, scale: 0.95, transition: { duration: DURATION.fast } },
};

export const staggerContainerVariants = {
  hidden: {},
  visible: { transition: { staggerChildren: STAGGER.normal, delayChildren: 0.05 } },
};

export const listItemVariants = {
  hidden: { opacity: 0, x: -12 },
  visible: { opacity: 1, x: 0, transition: { duration: DURATION.normal, ease: EASE.out } },
};
