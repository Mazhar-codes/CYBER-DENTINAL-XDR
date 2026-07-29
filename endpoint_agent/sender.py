"""
sender.py — Async HTTP sender for Cyber Sentinel XDR endpoint agent.

Sends telemetry payloads to the backend's /endpoint/ingest endpoint with
retry logic and exponential backoff.  Never raises — all errors are logged
and a boolean success flag is returned.
"""

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Retry configuration
_MAX_ATTEMPTS = 3
_BASE_BACKOFF_SECONDS = 1.0   # 1 s → 2 s → 4 s
_REQUEST_TIMEOUT_SECONDS = 10.0


async def send_telemetry(
    payload: dict[str, Any],
    backend_url: str,
    api_key: str,
) -> bool:
    """
    POST the telemetry payload to ``{backend_url}/endpoint/ingest``.

    Retries up to 3 times with exponential backoff (1 s, 2 s, 4 s) on any
    network or HTTP error.  Returns True only when the server responds with
    a 2xx status code on any attempt.

    Args:
        payload:     Serialisable dict built by the telemetry loop.
        backend_url: Base URL of the XDR backend (no trailing slash).
        api_key:     Value sent in the ``X-API-Key`` request header.

    Returns:
        True on success, False after all retries are exhausted.
    """
    url = f"{backend_url.rstrip('/')}/endpoint/ingest"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                logger.debug(
                    "Telemetry sent OK (attempt %d/%d, status %d, %d bytes)",
                    attempt,
                    _MAX_ATTEMPTS,
                    response.status_code,
                    len(response.content),
                )
                return True

            except httpx.HTTPStatusError as exc:
                logger.warning(
                    "Telemetry send HTTP error (attempt %d/%d): %s %s",
                    attempt,
                    _MAX_ATTEMPTS,
                    exc.response.status_code,
                    exc.response.text[:200],
                )
                # 4xx errors (bad request / auth failure) — no point retrying
                if 400 <= exc.response.status_code < 500:
                    logger.error(
                        "Non-retryable HTTP %d from backend — aborting send",
                        exc.response.status_code,
                    )
                    return False

            except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError) as exc:
                logger.warning(
                    "Telemetry send network error (attempt %d/%d): %s: %r  [url=%s]",
                    attempt,
                    _MAX_ATTEMPTS,
                    type(exc).__name__,
                    exc,
                    getattr(getattr(exc, "request", None), "url", "?"),
                )

            except Exception as exc:
                logger.error(
                    "Unexpected error during telemetry send (attempt %d/%d): %s",
                    attempt,
                    _MAX_ATTEMPTS,
                    exc,
                    exc_info=True,
                )

            # Backoff before next attempt (skip after last attempt)
            if attempt < _MAX_ATTEMPTS:
                backoff = _BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))
                logger.debug("Retrying telemetry send in %.1f s...", backoff)
                await asyncio.sleep(backoff)

    logger.error(
        "Telemetry send failed after %d attempts — backend may be unreachable",
        _MAX_ATTEMPTS,
    )
    return False


async def post_json(
    path: str,
    payload: dict[str, Any],
    backend_url: str,
    api_key: str,
    timeout: float = _REQUEST_TIMEOUT_SECONDS,
) -> tuple[bool, dict[str, Any]]:
    """
    Generic helper for one-shot authenticated POST requests to the backend.

    Used by command_listener to send acknowledgements.  Does not retry.

    Returns:
        (success: bool, response_body: dict)
    """
    url = f"{backend_url.rstrip('/')}/{path.lstrip('/')}"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            try:
                body = response.json()
            except Exception:
                body = {}
            return True, body
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "POST %s HTTP error %d: %s",
            path,
            exc.response.status_code,
            exc.response.text[:200],
        )
        return False, {}
    except Exception as exc:
        logger.warning("POST %s failed: %s", path, exc)
        return False, {}


async def get_json(
    path: str,
    params: dict[str, str],
    backend_url: str,
    api_key: str,
    timeout: float = _REQUEST_TIMEOUT_SECONDS,
) -> tuple[bool, Any]:
    """
    Generic helper for one-shot authenticated GET requests to the backend.

    Returns:
        (success: bool, parsed_json_body)
    """
    url = f"{backend_url.rstrip('/')}/{path.lstrip('/')}"
    headers = {"X-API-Key": api_key}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            try:
                return True, response.json()
            except Exception:
                return True, {}
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 403:
            logger.error(
                "GET %s rejected with 403 — check XDR_API_KEY", path
            )
        else:
            logger.warning(
                "GET %s HTTP error %d", path, exc.response.status_code
            )
        return False, {}
    except Exception as exc:
        logger.debug("GET %s failed: %s", path, exc)
        return False, {}
