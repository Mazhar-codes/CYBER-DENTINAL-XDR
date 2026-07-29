# Cyber Sentinel XDR — Frontend

React + TypeScript SOC dashboard (Create React App). Renders live alerts, SHAP
explanations, endpoint status, attack graph, and response/SOAR controls via Socket.IO
against the FastAPI backend in `../Backend/`.

**For full project setup (backend, MongoDB, endpoint agent, Suricata, etc.) see the
[repository root README](../README.md).** This file only covers this folder.

## Quick start

```bash
npm install
cp .env.example .env      # set REACT_APP_BACKEND_URL to your backend's address
npm start                 # http://localhost:3000
```

## Scripts

- `npm start` — dev server with hot reload
- `npm run build` — production build to `build/`
- `npm test` — CRA test runner

## Key source locations

- `src/components/` — dashboard views, tables, modals (`NetworkMonitor.tsx` is the top-level
  orchestrator owning Socket.IO state)
- `src/components/views/` — one file per sidebar view (Overview, Alerts, Endpoints, Network,
  Malware, Settings, Profile, Attack Graph, ...)
- `src/services/api.ts` — REST client; `src/services/networkSocket.ts` — Socket.IO subscriptions
- `src/types/network.ts` — TypeScript interfaces; source of truth for event/payload shapes
- `src/pages/` — auth flow (Login, Register, MFA setup, password recovery)

Bootstrapped with Create React App — standard CRA docs apply for anything not covered above:
https://facebook.github.io/create-react-app/docs/getting-started
