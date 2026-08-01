/**
 * Backend URL.
 *
 * Resolution priority:
 *   1. REACT_APP_BACKEND_URL if set at build time. Used in development
 *      (`npm start` on :3000 while the backend runs on another port) and for
 *      custom deployments where the API lives on a different host.
 *   2. Otherwise SAME-ORIGIN (`window.location.origin`). This is the packaged /
 *      production case: the backend itself serves these static dashboard files,
 *      so the REST API and Socket.IO are on the exact same origin the page was
 *      loaded from — any host, any port, http or https. No hardcoded IP, no
 *      per-install rebuild.
 *
 * The production build ships with REACT_APP_BACKEND_URL empty (see
 * .env.production) so it always resolves to same-origin.
 */
const _envUrl = (process.env.REACT_APP_BACKEND_URL ?? "").trim();

export const BACKEND_URL = _envUrl !== "" ? _envUrl : window.location.origin;
