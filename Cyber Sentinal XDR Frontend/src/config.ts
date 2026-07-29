/**
 * Backend URL — resolved at runtime from the browser's own hostname.
 *
 * When the user opens the dashboard via a LAN IP (e.g. http://10.173.3.60:3000)
 * the backend is always on the same machine, so we derive the URL from the
 * hostname directly.  This means switching networks (lab → hotspot → home)
 * never requires touching .env or restarting the dev-server.
 *
 * localhost / 127.0.0.1 fall back to REACT_APP_BACKEND_URL (or localhost:8000)
 * for cases where the backend might be on a different machine.
 */
const _hostname = window.location.hostname;
export const BACKEND_URL =
  _hostname !== "localhost" && _hostname !== "127.0.0.1"
    ? `http://${_hostname}:8000`
    : (process.env.REACT_APP_BACKEND_URL ?? "http://localhost:8000");
