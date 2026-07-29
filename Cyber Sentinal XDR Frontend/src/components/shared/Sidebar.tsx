import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import ThemeToggle from "../ThemeToggle";

export type ViewId =
  | "overview"
  | "network"
  | "attackgraph"
  | "userbehavior"
  | "alerts"
  | "endpoints"
  | "systemstatus"
  | "malware"
  | "sysmon"
  | "audit"
  | "settings"
  | "about"
  | "profile";

interface NavItem {
  id: ViewId;
  label: string;
  icon: string;
  badge?: number;
}

interface SidebarProps {
  activeView: ViewId;
  onNavigate: (view: ViewId) => void;
  isMonitoring: boolean;
  attackCount: number;
  anomalyCount: number;
  malwareCount?: number;
  sysmonCount?: number;
  endpointOnlineCount?: number;
  /** Non-zero when a response_required event has arrived and not yet acknowledged */
  responseRequiredCount?: number;
  /** Live alert count from the Attack Graph view */
  attackGraphAlertCount?: number;
  /** Current user role — hides Settings from viewers, attackgraph from viewers */
  userRole?: string;
  /** Current username — for user card */
  username?: string;
  /** Logout handler — called from user card Sign Out button */
  onLogout?: () => void;
}

const NAV_ITEMS: NavItem[] = [
  { id: "overview",     label: "Overview",        icon: "◈" },
  { id: "network",      label: "Network",         icon: "⬡" },
  { id: "attackgraph",  label: "Attack Graph",    icon: "◈" },
  { id: "userbehavior", label: "User Behavior",   icon: "◉" },
  { id: "alerts",       label: "Alerts",          icon: "◬" },
  { id: "endpoints",    label: "Endpoints",       icon: "▣" },
  { id: "systemstatus", label: "System Status",   icon: "◫" },
  { id: "malware",      label: "Malware",         icon: "⬣" },
  { id: "sysmon",       label: "Sysmon Behavior", icon: "⬡" },
];

const ROLE_COLORS: Record<string, { bg: string; text: string }> = {
  admin:   { bg: "rgba(255,0,68,0.15)",   text: "#ff6688" },
  analyst: { bg: "rgba(0,212,255,0.12)",  text: "#00d4ff" },
  viewer:  { bg: "rgba(0,255,136,0.10)",  text: "#00ff88" },
};

export default function Sidebar({
  activeView,
  onNavigate,
  isMonitoring,
  attackCount,
  anomalyCount,
  malwareCount = 0,
  sysmonCount = 0,
  endpointOnlineCount = 0,
  responseRequiredCount = 0,
  attackGraphAlertCount = 0,
  userRole,
  username,
  onLogout,
}: SidebarProps) {
  // Starts collapsed; expands on hover, collapses on mouse leave
  const [collapsed, setCollapsed] = useState(true);

  const badges: Partial<Record<ViewId, number>> = {
    network:      attackCount > 0 ? attackCount : 0,
    attackgraph:  attackGraphAlertCount > 0 ? attackGraphAlertCount : 0,
    userbehavior: anomalyCount > 0 ? anomalyCount : 0,
    alerts:       attackCount + anomalyCount > 0 ? attackCount + anomalyCount : 0,
    malware:      malwareCount > 0 ? malwareCount : 0,
    sysmon:       sysmonCount > 0 ? sysmonCount : 0,
    endpoints:    endpointOnlineCount > 0 ? endpointOnlineCount : 0,
  };

  const hasResponseRequired = responseRequiredCount > 0;

  // Filter nav items based on role
  const visibleNavItems = NAV_ITEMS.filter((item) => {
    if (item.id === "attackgraph" && userRole === "viewer") return false;
    return true;
  });

  const initials = username ? username.slice(0, 2).toUpperCase() : "?";
  const roleStyle = ROLE_COLORS[userRole ?? "viewer"] ?? ROLE_COLORS.viewer;

  // Bottom utility buttons (Audit, Profile, Settings, About)
  const bottomItems: { id: ViewId; icon: string; label: string; hidden?: boolean }[] = [
    { id: "audit",    icon: "◑", label: "Audit Log", hidden: userRole !== "admin" },
    { id: "profile",  icon: "◉", label: "Profile" },
    { id: "settings", icon: "⚙", label: "Settings", hidden: userRole === "viewer" },
    { id: "about",    icon: "◎", label: "About" },
  ];

  const renderNavButton = (
    item: { id: ViewId; icon: string; label: string },
    badgeCount?: number,
    extraStyle?: React.CSSProperties
  ) => {
    const isActive = activeView === item.id;
    const isEndpoints = item.id === "endpoints";
    const activeBarColor = isActive ? "var(--accent-cyan)" : isEndpoints && hasResponseRequired ? "#ef4444" : "transparent";
    return (
      <motion.div
        key={item.id}
        whileHover={{ x: 3 }}
        transition={{ duration: 0.15 }}
        style={{ position: "relative", width: "100%" }}
      >
        {/* Sliding active indicator */}
        {(isActive || (isEndpoints && hasResponseRequired)) && (
          <motion.div
            layoutId="sidebar-active"
            style={{
              position: "absolute",
              left: 0,
              top: 0,
              bottom: 0,
              width: 3,
              background: activeBarColor,
              borderRadius: "0 2px 2px 0",
            }}
            transition={{ type: "spring", stiffness: 400, damping: 35 }}
          />
        )}
        <button
          onClick={() => onNavigate(item.id)}
          title={collapsed ? item.label : undefined}
          className="sidebar-item"
          style={{
            width: "100%",
            display: "flex",
            alignItems: "center",
            gap: 12,
            padding: collapsed ? "12px 0" : "12px 16px",
            justifyContent: collapsed ? "center" : "flex-start",
            background: isActive
              ? "linear-gradient(90deg, rgba(47,224,224,0.10) 0%, transparent 100%)"
              : isEndpoints && hasResponseRequired
              ? "rgba(220,38,38,0.06)"
              : "transparent",
            borderLeft: "3px solid transparent",
            border: "none",
            borderRight: "none",
            cursor: "pointer",
            transition: "all 0.15s ease",
            position: "relative",
            ...extraStyle,
          }}
        >
        <span
          style={{
            fontSize: 18,
            color: isActive
              ? "var(--accent-cyan)"
              : isEndpoints && hasResponseRequired
              ? "#ff6688"
              : "var(--text-muted)",
            flexShrink: 0,
            transition: "color 0.15s",
            lineHeight: 1,
          }}
        >
          {item.icon}
        </span>
        <AnimatePresence initial={false}>
          {!collapsed && (
            <motion.span
              key="label"
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: "auto" }}
              exit={{ opacity: 0, width: 0 }}
              transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
              style={{
                fontSize: 14,
                fontWeight: isActive ? 700 : 500,
                color: isActive
                  ? "var(--text-primary)"
                  : isEndpoints && hasResponseRequired
                  ? "#fca5a5"
                  : "var(--text-muted)",
                transition: "color 0.15s",
                flex: 1,
                textAlign: "left",
                whiteSpace: "nowrap",
                overflow: "hidden",
                display: "block",
              }}
            >
              {item.label}
            </motion.span>
          )}
        </AnimatePresence>
        {/* Badge — expanded */}
        <AnimatePresence initial={false}>
          {!collapsed && (badgeCount ?? 0) > 0 && (
            <motion.span
              key="badge"
              initial={{ opacity: 0, scale: 0.7 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.7 }}
              transition={{ duration: 0.15 }}
              style={{
                background:
                  item.id === "userbehavior" ? "#ea580c"
                  : item.id === "malware" ? "#7c3aed"
                  : item.id === "sysmon" ? "#0891b2"
                  : item.id === "endpoints" ? "#00d4ff"
                  : item.id === "attackgraph" ? "#dc2626"
                  : "#ef4444",
                color: "#fff",
                borderRadius: 10,
                padding: "1px 7px",
                fontSize: 10,
                fontWeight: 700,
                minWidth: 18,
                textAlign: "center",
                flexShrink: 0,
              }}
            >
              {(badgeCount ?? 0) > 99 ? "99+" : badgeCount}
            </motion.span>
          )}
        </AnimatePresence>
        {/* Response-required urgent badge on Endpoints — expanded */}
        <AnimatePresence initial={false}>
          {!collapsed && isEndpoints && hasResponseRequired && (
            <motion.span
              key="respond-badge"
              initial={{ opacity: 0, scale: 0.7 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.7 }}
              transition={{ duration: 0.15 }}
              style={{
                background: "#dc2626",
                color: "#fff",
                borderRadius: 10,
                padding: "1px 7px",
                fontSize: 10,
                fontWeight: 800,
                letterSpacing: 0.5,
                textTransform: "uppercase",
                animation: "xdr-pulse 1s ease-in-out infinite",
                boxShadow: "0 0 8px rgba(220,38,38,0.6)",
                flexShrink: 0,
              }}
            >
              RESPOND
            </motion.span>
          )}
        </AnimatePresence>
        {/* Collapsed dots */}
        {collapsed && (badgeCount ?? 0) > 0 && (
          <span
            style={{
              position: "absolute",
              top: 8,
              right: 8,
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: "#ef4444",
              boxShadow: "0 0 6px #ef4444",
            }}
          />
        )}
        {collapsed && isEndpoints && hasResponseRequired && (
          <span
            style={{
              position: "absolute",
              top: 6,
              right: 6,
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: "#dc2626",
              boxShadow: "0 0 8px #dc2626",
              animation: "xdr-pulse 1s ease-in-out infinite",
            }}
          />
        )}
        </button>
      </motion.div>
    );
  };

  return (
    <motion.div
      data-sidebar="true"
      onMouseEnter={() => setCollapsed(false)}
      onMouseLeave={() => setCollapsed(true)}
      animate={{ width: collapsed ? 80 : 250 }}
      transition={{ duration: 0.3, ease: [0.4, 0, 0.2, 1] }}
      style={{
        minHeight: "100vh",
        background: "var(--bg-sidebar)",
        borderRight: "1px solid var(--border-color)",
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        position: "relative",
        zIndex: 10,
        overflow: "hidden",
      }}
    >
      {/* Logo / Brand */}
      <div
        style={{
          padding: collapsed ? "20px 0" : "20px 16px",
          borderBottom: "1px solid var(--border-color)",
          display: "flex",
          alignItems: "center",
          gap: 10,
          justifyContent: collapsed ? "center" : "flex-start",
          minHeight: 72,
          transition: "padding 0.3s ease",
        }}
      >
        <div
          style={{
            width: 42,
            height: 42,
            borderRadius: 10,
            background: "var(--bg-primary)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
            boxShadow: "var(--shadow-glow-cyan)",
            overflow: "hidden",
            border: "1px solid var(--border-color-strong)",
          }}
        >
          <img
            src="/logo.jpg"
            alt="Cyber Sentinel XDR"
            style={{ width: "100%", height: "100%", objectFit: "cover", display: "block" }}
          />
        </div>
        <AnimatePresence initial={false}>
          {!collapsed && (
            <motion.div
              key="brand-text"
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.2 }}
            >
              <div style={{ color: "var(--text-heading)", fontWeight: 800, fontSize: 14, letterSpacing: 0.5, whiteSpace: "nowrap" }}>
                CYBER SENTINEL
              </div>
              <div style={{ color: "var(--accent-cyan)", fontSize: 10, fontWeight: 700, letterSpacing: 2, marginTop: 1, whiteSpace: "nowrap" }}>
                XDR PLATFORM
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Monitoring status indicator */}
      <div
        style={{
          padding: collapsed ? "12px 0" : "12px 16px",
          borderBottom: "1px solid var(--border-color)",
          display: "flex",
          alignItems: "center",
          gap: 8,
          justifyContent: collapsed ? "center" : "flex-start",
          transition: "padding 0.3s ease",
        }}
      >
        <span
          style={{
            display: "inline-block",
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: isMonitoring ? "#22c55e" : "var(--text-muted)",
            boxShadow: isMonitoring ? "0 0 8px #22c55e" : "none",
            animation: isMonitoring ? "xdr-pulse 1.4s ease-in-out infinite" : "none",
            flexShrink: 0,
          }}
        />
        <AnimatePresence initial={false}>
          {!collapsed && (
            <motion.span
              key="monitor-label"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.18 }}
              style={{
                fontSize: 11,
                fontWeight: 700,
                color: isMonitoring ? "#22c55e" : "var(--text-muted)",
                letterSpacing: 1,
                textTransform: "uppercase",
                whiteSpace: "nowrap",
              }}
            >
              {isMonitoring ? "Monitoring Active" : "Monitoring Idle"}
            </motion.span>
          )}
        </AnimatePresence>
      </div>

      {/* Nav Items */}
      <nav style={{ flex: 1, padding: "8px 0", overflowY: "auto", overflowX: "hidden" }}>
        {visibleNavItems.map((item) => {
          const badgeCount = badges[item.id] ?? 0;
          return renderNavButton(item, badgeCount);
        })}
      </nav>

      {/* Bottom section — Theme Toggle, Profile, Settings, About, User Card */}
      <div
        style={{
          borderTop: "1px solid var(--border-color)",
          paddingTop: 8,
          paddingBottom: 8,
        }}
      >
        {/* Profile / Settings / About buttons */}
        {bottomItems
          .filter((item) => !item.hidden)
          .map((item) => {
            const isActive = activeView === item.id;
            return (
              <motion.div
                key={item.id}
                whileHover={{ x: 3 }}
                transition={{ duration: 0.15 }}
                style={{ position: "relative", width: "100%" }}
              >
                {isActive && (
                  <motion.div
                    layoutId="sidebar-active"
                    style={{
                      position: "absolute",
                      left: 0,
                      top: 0,
                      bottom: 0,
                      width: 3,
                      background: "var(--accent-cyan)",
                      borderRadius: "0 2px 2px 0",
                    }}
                    transition={{ type: "spring", stiffness: 400, damping: 35 }}
                  />
                )}
                <button
                  onClick={() => onNavigate(item.id)}
                  title={collapsed ? item.label : undefined}
                  className="sidebar-item"
                  style={{
                    width: "100%",
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: collapsed ? "10px 0" : "10px 16px",
                    justifyContent: collapsed ? "center" : "flex-start",
                    background: isActive
                      ? "linear-gradient(90deg, rgba(47,224,224,0.10) 0%, transparent 100%)"
                      : "transparent",
                    borderLeft: "3px solid transparent",
                    border: "none",
                    borderRight: "none",
                    cursor: "pointer",
                    transition: "all 0.15s ease",
                  }}
                >
                  <span
                    style={{
                      fontSize: 16,
                      color: isActive ? "var(--accent-cyan)" : "var(--text-muted)",
                      flexShrink: 0,
                      transition: "color 0.15s",
                      lineHeight: 1,
                    }}
                  >
                    {item.icon}
                  </span>
                  <AnimatePresence initial={false}>
                    {!collapsed && (
                      <motion.span
                        key={`bottom-label-${item.id}`}
                        initial={{ opacity: 0, width: 0 }}
                        animate={{ opacity: 1, width: "auto" }}
                        exit={{ opacity: 0, width: 0 }}
                        transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
                        style={{
                          fontSize: 13,
                          fontWeight: isActive ? 700 : 500,
                          color: isActive ? "var(--text-primary)" : "var(--text-muted)",
                          transition: "color 0.15s",
                          flex: 1,
                          textAlign: "left",
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          display: "block",
                        }}
                      >
                        {item.label}
                      </motion.span>
                    )}
                  </AnimatePresence>
                </button>
              </motion.div>
            );
          })}

        {/* Theme Toggle */}
        <div style={{ padding: collapsed ? "0" : "0 4px" }}>
          <ThemeToggle compact={collapsed} />
        </div>

        {/* User card + Sign Out */}
        <div
          style={{
            margin: collapsed ? "8px 6px 0" : "8px 10px 0",
            borderRadius: 10,
            background: "var(--bg-card)",
            border: "1px solid var(--border-color)",
            padding: collapsed ? "10px 0" : "10px 12px",
            display: "flex",
            flexDirection: collapsed ? "column" : "row",
            alignItems: "center",
            gap: collapsed ? 6 : 10,
            justifyContent: collapsed ? "center" : "flex-start",
            transition: "padding 0.3s ease, margin 0.3s ease",
            overflow: "hidden",
          }}
        >
          {/* Avatar circle */}
          <div
            style={{
              width: collapsed ? 28 : 32,
              height: collapsed ? 28 : 32,
              borderRadius: "50%",
              background: `linear-gradient(135deg, ${roleStyle.text}44, ${roleStyle.text}22)`,
              border: `1px solid ${roleStyle.text}55`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: collapsed ? 11 : 13,
              fontWeight: 800,
              color: roleStyle.text,
              flexShrink: 0,
              transition: "width 0.3s, height 0.3s, font-size 0.3s",
            }}
          >
            {initials}
          </div>

          {/* Name + role (expanded only) */}
          <AnimatePresence initial={false}>
            {!collapsed && (
              <motion.div
                key="user-info"
                initial={{ opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: "auto" }}
                exit={{ opacity: 0, width: 0 }}
                transition={{ duration: 0.2 }}
                style={{ flex: 1, minWidth: 0, overflow: "hidden" }}
              >
                <div
                  style={{
                    fontSize: 13,
                    fontWeight: 700,
                    color: "var(--text-primary)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    lineHeight: 1.2,
                  }}
                >
                  {username ?? "Unknown"}
                </div>
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 800,
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    color: roleStyle.text,
                    background: roleStyle.bg,
                    borderRadius: 4,
                    padding: "1px 5px",
                    display: "inline-block",
                    marginTop: 2,
                  }}
                >
                  {userRole ?? "viewer"}
                </span>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Sign Out button */}
          {onLogout && (
            <button
              onClick={onLogout}
              title="Sign Out"
              style={{
                padding: collapsed ? "4px 0" : "5px 8px",
                borderRadius: 6,
                border: "1px solid rgba(255,51,102,0.25)",
                background: "transparent",
                color: "#ff6688",
                fontSize: collapsed ? 14 : 12,
                cursor: "pointer",
                fontWeight: 700,
                letterSpacing: 0.3,
                flexShrink: 0,
                lineHeight: 1,
                transition: "all 0.15s",
                minWidth: collapsed ? 28 : "auto",
                textAlign: "center",
              }}
            >
              {collapsed ? "⇥" : "Sign Out"}
            </button>
          )}
        </div>
      </div>
    </motion.div>
  );
}
