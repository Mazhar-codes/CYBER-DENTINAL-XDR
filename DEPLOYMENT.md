# Cyber Sentinel XDR — Deployment & Topology Guide

This guide explains how to deploy Cyber Sentinel XDR correctly, whether on a
single machine (dev/demo) or across many devices (production), and how to avoid
the "collision" problems that come from running the server and an endpoint on the
same host. Read §2 (the golden rule) first — everything else follows from it.

---

## 1. Architecture in one picture

```
   ┌─────────────────────────────────────────────────────────────┐
   │                     XDR SERVER  (the "brain")                 │
   │  FastAPI + Socket.IO backend  ·  ML models  ·  MongoDB         │
   │  Dashboard (React)  ·  Response engine  ·  Attack graph        │
   └───────────▲─────────────────────────────────────▲────────────┘
               │ HTTP  POST /endpoint/ingest          │ WebSocket
               │ (telemetry + honeypot hits)          │ (live UI)
   ┌───────────┴──────────┐   ┌──────────────┐   ┌────┴────────────┐
   │  Endpoint Agent (PC1) │   │  Agent (PC2)  │   │  SOC Dashboard  │
   │  psutil telemetry     │   │     ...       │   │   (browser)     │
   │  honeypot decoy ports │   └──────────────┘   └─────────────────┘
   │  (optional) Suricata  │
   └──────────────────────┘
```

- **Server = the brain.** It never reaches out to endpoints; endpoints report *to* it.
- **Agent = one sensor per device.** Lightweight, uses psutil for system/network/user
  telemetry + a deception honeypot. Sends everything over authenticated HTTP.
- The agent is the unit you replicate: to add a device, install the agent, point it
  at the server URL, done.

---

## 2. The golden rule: **monitor each machine exactly once**

Every machine is monitored **either** by the agent running on it **or** by the
backend's built-in self-monitoring — **never both.** Violating this is the root of
almost every "duplicate/collision/flapping/high-CPU" problem:

- Same host reported under two identities (`server_host` **and** an agent `endpoint_id`)
- Double telemetry, double alerts, double CPU load (two sets of ML inference loops)
- Two Suricata processes fighting over the same NIC and the same `eve.json`

**Corollary rules (all follow from the golden rule):**

1. **One backend per host** (enforced by the single-instance guard, see §7).
2. **One agent per device**, one stable `endpoint_id`.
3. **One Suricata at most per device** (see §5).
4. **Start each component from exactly one launcher** (see §8).

---

## 3. Deployment modes

### Mode A — All-in-one (single machine) — dev / demo / thesis
Backend + one agent + dashboard all on one box. This is the collapsed form of the
production topology and is perfect for development.

- Backend self-monitoring: **OFF** (`XDR_SELF_MONITOR=false`) — the agent is this
  machine's sensor, so the backend must not also monitor it.
- Suricata: **server-side, auto-detected interface** (see §5). On one box it captures
  the same NIC the agent uses, which is exactly the endpoint's traffic — no need for
  endpoint-side Suricata yet.
- Result: the machine is reported once (by the agent), CPU stays low, no collisions.

### Mode B — Distributed (1 server + N endpoints) — production
- **Server host:** runs the backend, MongoDB, and the dashboard. Whether it monitors
  *itself* depends on its role (see §4).
- **Each endpoint device:** runs one agent, pointed at the server's URL.
- Suricata: consider moving it **to the endpoints** so each device's own traffic is
  inspected (see §5, "Migration").

---

## 4. Server self-monitoring — `XDR_SELF_MONITOR`

"Self-monitoring" = the backend running its **own** local collection loops
(system/psutil, Sysmon, user-behavior, and the server-side Suricata/network loop) so
the server machine is watched as if it were an endpoint.

Set it by the host's **role**, using the golden rule:

| Host situation | `XDR_SELF_MONITOR` |
|---|---|
| Backend host **also runs the agent** (e.g. all-in-one laptop) | `false` |
| Dedicated server, **no agent installed on it** | `true` |
| Dedicated server that **also runs an agent** | `false` |

> The ML **inference** used to score *incoming endpoint* telemetry is always active —
> disabling self-monitoring only stops the backend from collecting/scoring **its own
> host** as a second identity. Endpoint scoring is unaffected.

**This is not a laptop-only setting.** The *principle* (monitor once) is universal;
the *value* depends on whether that specific box runs an agent.

---

## 5. Suricata placement & migration

Suricata gives **packet-level / signature-based** network detection that psutil
cannot (psutil only sees connection metadata: IP, port, state, byte counts).

### Now — server-side, auto-detected interface
The backend launches Suricata and **auto-detects the active capture interface** at
Start Monitoring (the "Up" adapter that owns the default gateway). No hardcoded GUID.
Override with `XDR_SURICATA_INTERFACE` if you must force one.

- Single machine: server-side Suricata captures the one NIC = the endpoint's traffic.
  Perfectly adequate. **Do NOT also run Suricata on the agent here** — two Suricata on
  one NIC is a collision for zero benefit.
- Server-at-a-chokepoint (SPAN/gateway): server-side Suricata monitoring the segment is
  a legitimate NDR design on its own.

### Migration — move Suricata to the endpoints (only when devices split)
The day an agent runs on a **separate** machine, the server-side Suricata goes **blind**
to that device (it can only see the server's own NIC). *That* is when — and only when —
you move Suricata to the agent:

1. Install Suricata + npcap on the endpoint (agent runs as Administrator already).
2. Add a Suricata collector to the agent that tails the endpoint's local `eve.json`
   and includes recent flows in the telemetry payload's **`suricata`** field.
   *(The backend already accepts and scores `payload.suricata` — no server redesign;
   this is roughly a one-day change, not an architecture rewrite.)*
3. On that endpoint's server: nothing changes. On the server host, if it's no longer
   watching a segment, you can leave server-side Suricata off.

**Rule of thumb:** migrate when the need is real (devices actually separated), not before.

---

## 6. Network interface auto-detection

Both the backend (for Suricata) and the agent (for the `isolate_host` SOAR action)
detect the active adapter at runtime instead of hardcoding a GUID/name — so the same
build works on Wi-Fi or Ethernet, on any machine, and survives adapter reinstalls.

- Backend Suricata interface: auto-detected; override with `XDR_SURICATA_INTERFACE`
  (`\Device\NPF_{GUID}` or bare `{GUID}`).
- Agent isolation interface: auto-detected (Ethernet → Wi-Fi → Wireless priority);
  override with `XDR_ISOLATE_INTERFACE`.

To find a machine's active adapter GUID manually:
```powershell
Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway} | ForEach-Object {
  (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex) | Select-Object Name, InterfaceGuid
}
```

---

## 7. Collision-avoidance checklist

- [ ] **Exactly one backend.** The backend takes a single-instance lock on startup
      (`XDR_SINGLETON_GUARD`, guard port `XDR_SINGLETON_GUARD_PORT`, default 8123). A
      second backend logs `ANOTHER CYBER SENTINEL BACKEND IS ALREADY RUNNING` and exits.
      Do **not** start the backend from two places (e.g. a terminal *and* a launcher).
- [ ] **Exactly one agent** per device, with one persisted `endpoint_id`
      (`endpoint_config.json`). Don't start it from two launchers.
- [ ] **`XDR_SELF_MONITOR=false`** on any host that also runs the agent (§4).
- [ ] **One Suricata** per device, auto-detected interface (§5). Kill strays:
      `Get-Process suricata -ErrorAction SilentlyContinue | Stop-Process -Force`
- [ ] **Honeypot only on the agent** (decoy ports bound by the endpoint agent).

---

## 8. Startup order & the one-launcher rule

**Pick one launch path and stick to it.** Mixing a manual `uvicorn` with a launcher
button, or starting the agent from two GUIs, is what creates duplicates.

Recommended order (all-in-one):
1. **Backend** — `uvicorn backend:sio_app --host 0.0.0.0 --port 8000` (from `Backend/`,
   venv activated). Wait for `Application startup complete`.
2. **Frontend** — serve the built bundle (`npm run build` then serve `build/`), or
   `npm start` for dev.
3. **Agent** — from a single launcher. Its honeypot starts with it.
4. In the dashboard → **Start Monitoring once.** (This is what starts Suricata + the
   server-side loops.)

> After changing frontend source, you must `npm run build` — the launcher serves the
> prebuilt `build/` folder, so source edits don't appear until rebuilt.

---

## 9. Ports reference

| Port | Component | Bind |
|---|---|---|
| 8000 | Backend (FastAPI/Socket.IO) | `0.0.0.0` |
| 3000 | Frontend (React) | `0.0.0.0` |
| 8123 | Backend single-instance guard | `127.0.0.1` |
| 8765 | Agent health endpoint | `0.0.0.0` |
| 23,21,2222,3306,1433,5900,8080 | Agent honeypot decoy ports | `0.0.0.0` |
| 27017 | MongoDB (if local) | as configured |

---

## 10. Environment variables reference

**Backend** (`Backend/.env`):

| Var | Purpose | Default |
|---|---|---|
| `JWT_SECRET_KEY` | JWT signing secret (**must set**) | — |
| `XDR_API_KEY` | API key endpoints must present (**must set**) | — |
| `XDR_SELF_MONITOR` | Monitor the server host itself (§4) | role-based |
| `XDR_SURICATA_INTERFACE` | Force Suricata capture interface (§6) | auto-detect |
| `XDR_SYSTEM_MONITOR_INTERVAL` | Seconds between system-monitor ticks | `5` |
| `MALWARE_SCAN_INTERVAL` | Malware file-watcher interval (s) | `120` |
| `XDR_SINGLETON_GUARD` | Enable single-instance guard | `1` |
| `XDR_SINGLETON_GUARD_PORT` | Guard lock port | `8123` |
| `XDR_ISOLATE_INTERFACE` | NIC for server-side `isolate_host` | auto |

**Agent** (`endpoint_agent/.env`):

| Var | Purpose | Default |
|---|---|---|
| `XDR_BACKEND_URL` | Server URL the agent reports to | `http://127.0.0.1:8000` |
| `XDR_API_KEY` | Must match the backend's key | `changeme-dev-key` |
| `XDR_COLLECT_INTERVAL` | Telemetry interval (s) | `5` |
| `XDR_COMMAND_INTERVAL` | Command poll interval (s) | `3` |
| `XDR_HONEYPOT_ENABLED` | Enable decoy-port honeypot | `true` |
| `XDR_HONEYPOT_PORTS` | Comma-separated decoy ports | built-in set |

**Frontend** (`.env`):

| Var | Purpose | Default |
|---|---|---|
| `REACT_APP_BACKEND_URL` | Backend URL the dashboard calls | `http://localhost:8000` |
| `REACT_APP_ATTACK_GRAPH_DEMO` | Show the canned demo attack graph | `false` (real data only) |

---

## 11. Going distributed — step by step

1. **Server host:** set a strong `JWT_SECRET_KEY` + `XDR_API_KEY`, decide
   `XDR_SELF_MONITOR` by role (§4), bind the backend to `0.0.0.0:8000`, open the
   firewall for 8000 (and 3000 if the dashboard is remote).
2. **Each endpoint:** install the agent, set `XDR_BACKEND_URL=http://<server-ip>:8000`
   and the matching `XDR_API_KEY`. First run generates a unique `endpoint_id`.
3. Set `REACT_APP_BACKEND_URL` to the server's URL and rebuild the frontend.
4. (Optional) When endpoints are truly separate machines, migrate Suricata to the
   agents (§5).
5. **Production hardening** (see also the project's "Still Outstanding" notes): HTTPS/mTLS
   between agent and server, JWT in httpOnly cookies, a Redis/Mongo-backed rate limiter,
   run the agent as a Windows Service (NSSM), and configure a trusted-proxy list for
   `X-Forwarded-For`.

---

## 12. Troubleshooting (issues seen in practice)

| Symptom | Cause | Fix |
|---|---|---|
| Backend "closes itself"; agent gets random timeouts; dashboard empty | **Two backends** bound to 8000 (Windows lets both bind; connections split) | Single-instance guard now blocks it. Don't start the backend twice. |
| Agent times out ~10s after Start Monitoring | Backend event loop blocked by heavy synchronous work (e.g. malware walk over `C:\Users`, back-to-back RandomForest) | Malware walk is now threaded + pruned; system-monitor interval raised to 5s; set `XDR_SELF_MONITOR=false` to stop double-monitoring load. |
| Suricata dot red / `0 flows for N cycles` | Hardcoded interface GUID no longer matches the NIC | Interface is now auto-detected. Ensure only one Suricata runs; kill strays. |
| Honeypot panel empty even after a scan | Backend crashed serializing a `datetime` in the `honeypot_alert` emit | Fixed (datetime stripped from the socket payload). Trigger a probe with the dashboard open (history isn't re-fetched on refresh). |
| Attack graph shows machines you don't own (DEV-MAC-12, WIN-DC01, …) | Frontend demo/mock fallback | Disabled by default. Re-enable only for presentations with `REACT_APP_ATTACK_GRAPH_DEMO=true`. |
| Endpoint flaps offline | Telemetry failed > 35s (heartbeat threshold) during a load spike/scan | Resolve the load cause above; it re-registers once telemetry is steady. |

---

---

## 13. Production hardening — reverse proxy (the permanent `WinError 64` fix)

**Symptom:** after an aggressive port scan (e.g. nmap) hits the backend's port, the
agent starts logging `All connection attempts failed` and the endpoint goes offline —
even though the backend process is still alive and printing background logs. The
server console shows:

```
[WinError 64] The specified network name is no longer available
Accept failed on a socket  socket: <...laddr=('0.0.0.0', 8000)>
```

**Cause:** uvicorn runs on asyncio's Windows `ProactorEventLoop`. Malformed/abrupt
connections from a scan can kill its **accept loop**, leaving the process alive but
no longer accepting connections (a "zombie" backend). This is an **OS-level asyncio
fragility, not an app bug** — there is no reliable in-code fix, and restarting the
backend is the only recovery.

**Permanent fix (all users, all endpoints, Windows-native):** put a hardened reverse
proxy in front of uvicorn and bind uvicorn to **loopback only**. The proxy absorbs the
raw/malicious traffic; uvicorn only ever receives clean HTTP and is never exposed to a
scan again. This is the standard production deployment for uvicorn/FastAPI.

```
endpoints / browsers ──► Caddy (0.0.0.0:8000) ──► uvicorn (127.0.0.1:8001)
```

Because everything already targets port 8000, **nothing in the agent or frontend
changes** — Caddy takes over :8000 and uvicorn moves to loopback :8001.

**Setup (Windows):**
1. Install Caddy: `winget install CaddyServer.Caddy`
2. Start the backend on loopback: `uvicorn backend:sio_app --host 127.0.0.1 --port 8001`
3. Start Caddy from the repo root: `caddy run --config Caddyfile`

The ready-to-use `Caddyfile` is at the repo root. It serves plain HTTP by default
(fixes the scan problem immediately, no certs) and includes a commented **HTTPS**
block — switch to it for real deployments so the API key stops travelling in
plaintext (Caddy auto-manages certificates; use `tls internal` for a LAN with no
public domain).

> **Platform note:** `WinError 64` is Windows-`ProactorEventLoop`-specific and does
> not occur on Linux (`epoll`). A Windows server behind Caddy is fully fine — the OS
> choice is independent of the (Windows) endpoints. Keeping everything on Windows is
> valid; the reverse proxy is what makes it robust.

**Single-machine dev shortcut (no proxy):** bind uvicorn to `--host 127.0.0.1`
directly. A scan of the machine's LAN/VBox IP then finds nothing on 8000, so it can't
break the listener, while the agent's honeypot (bound on all interfaces) still fires.
This is the quick dev workaround; the reverse proxy is the real fix for distributed use.

**Defense-in-depth (optional, not the primary fix):**
- Run the backend under a supervisor (**NSSM** on Windows / systemd on Linux) with
  auto-restart, plus a watchdog that pings `/health` and restarts a zombie backend.
- OS firewall / fail2ban to drop aggressive scanners before they reach the proxy.

---

*Keep this file updated as the topology evolves. The single most important line in it
is §2: monitor each machine exactly once.*
