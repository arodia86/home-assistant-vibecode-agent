"""
HA Privacy Proxy
================
A transparent reverse proxy that sits between the MCP client and the
HA Vibecode Agent.  It redacts PII/sensitive data in responses heading
to Claude, and restores the original values in requests coming back
from Claude before they reach the agent.

Flow:
  MCP client → Privacy Proxy (port 8098)
                  ├── request  → restore tokens → Agent (port 8099)
                  └── response ← sanitize PII  ← Agent (port 8099)

The proxy adds a small admin endpoint:
  GET /privacy/status   – see how many tokens are in use
  GET /privacy/tokens   – list all active tokens (no originals shown)
  DELETE /privacy/mapping – clear the mapping (use with care)
"""

import json
import logging
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .sanitizer import PrivacySanitizer

# ── Config from environment (set by run.sh) ──────────────────────────────────
AGENT_URL = os.environ.get("AGENT_URL", "http://localhost:8099")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8098"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info").upper()

_names_raw = os.environ.get("PERSONAL_NAMES", "")
_words_raw = os.environ.get("CUSTOM_WORDS", "")
_domains_raw = os.environ.get("ENTITY_DOMAINS", "person")

PERSONAL_NAMES = [n.strip() for n in _names_raw.split(",") if n.strip()]
CUSTOM_WORDS = [w.strip() for w in _words_raw.split(",") if w.strip()]
ENTITY_DOMAINS = [d.strip() for d in _domains_raw.split(",") if d.strip()]

REDACT_IPS = os.environ.get("REDACT_IPS", "true").lower() == "true"
REDACT_MACS = os.environ.get("REDACT_MACS", "true").lower() == "true"
REDACT_EMAILS = os.environ.get("REDACT_EMAILS", "true").lower() == "true"
REDACT_PHONES = os.environ.get("REDACT_PHONES", "false").lower() == "true"
REDACT_GPS = os.environ.get("REDACT_GPS", "true").lower() == "true"

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("privacy_proxy")

# ── Sanitizer (singleton) ─────────────────────────────────────────────────────
sanitizer = PrivacySanitizer(
    personal_names=PERSONAL_NAMES,
    custom_words=CUSTOM_WORDS,
    entity_domains=ENTITY_DOMAINS,
    redact_ips=REDACT_IPS,
    redact_macs=REDACT_MACS,
    redact_emails=REDACT_EMAILS,
    redact_phones=REDACT_PHONES,
    redact_gps=REDACT_GPS,
)


# ── App lifecycle ─────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Try to pre-load entity names from the agent so person.* entities are
    # automatically redacted even without explicit personal_names config.
    await _prefetch_entity_names()
    yield


async def _prefetch_entity_names() -> None:
    """Fetch entities from the agent to seed the sanitizer with person names."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{AGENT_URL}/api/entities/list")
            if resp.status_code == 200:
                data = resp.json()
                entities = data if isinstance(data, list) else data.get("entities", [])
                sanitizer.add_entity_names(entities)
                logger.info("Privacy proxy: pre-fetched %d entities from agent", len(entities))
            else:
                logger.warning(
                    "Privacy proxy: entity pre-fetch returned %d (auth required? "
                    "Add API key to entity_prefetch_key config option)",
                    resp.status_code,
                )
    except Exception as exc:
        logger.warning("Privacy proxy: could not pre-fetch entities: %s", exc)


app = FastAPI(
    title="HA Privacy Proxy",
    version="1.0.0",
    description="Transparent privacy sanitization layer for HA Vibecode Agent",
    lifespan=lifespan,
)


# ── Admin endpoints ───────────────────────────────────────────────────────────

@app.get("/privacy/status")
async def privacy_status():
    """Show how many tokens are active and which PII categories are enabled."""
    summary = sanitizer.get_mapping_summary()
    return {
        "proxy_version": "1.0.0",
        "agent_url": AGENT_URL,
        "active_tokens": summary["token_count"],
        "categories_seen": summary["categories"],
        "settings": {
            "redact_ips": REDACT_IPS,
            "redact_macs": REDACT_MACS,
            "redact_emails": REDACT_EMAILS,
            "redact_phones": REDACT_PHONES,
            "redact_gps": REDACT_GPS,
            "personal_names_configured": len(PERSONAL_NAMES),
            "custom_words_configured": len(CUSTOM_WORDS),
            "entity_domains": ENTITY_DOMAINS,
        },
    }


@app.get("/privacy/tokens")
async def privacy_tokens():
    """List active tokens (safe to share – originals are NOT included)."""
    summary = sanitizer.get_mapping_summary()
    return {"tokens": summary["tokens"]}


@app.delete("/privacy/mapping")
async def clear_mapping():
    """
    Clear the token mapping.  After this, new tokens will be assigned.
    WARNING: any Claude conversation holding old tokens will no longer
    be restorable – only use between sessions.
    """
    import os as _os
    from .sanitizer import MAPPING_FILE

    sanitizer._fwd.clear()
    sanitizer._rev.clear()
    try:
        _os.remove(MAPPING_FILE)
    except FileNotFoundError:
        pass
    logger.info("Privacy proxy: mapping cleared by admin request")
    return {"cleared": True}


# ── Reverse proxy (catch-all) ─────────────────────────────────────────────────

_HOP_BY_HOP = frozenset([
    "host", "content-length", "transfer-encoding",
    "te", "connection", "keep-alive", "upgrade",
    "proxy-authenticate", "proxy-authorization", "trailer",
])


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str) -> Response:
    # ── 1. Read and restore tokens in the incoming request ──────────────────
    raw_body = await request.body()
    body_bytes = _restore_body(raw_body, request.headers.get("content-type", ""))

    # Restore tokens that may have appeared in URL path or query string
    clean_path = sanitizer.restore(path)
    clean_params = {k: sanitizer.restore(v) for k, v in request.query_params.items()}

    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }

    # ── 2. Forward to the real agent ─────────────────────────────────────────
    target_url = f"{AGENT_URL}/{clean_path}"
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                content=body_bytes,
                params=clean_params,
                follow_redirects=True,
            )
        except httpx.RequestError as exc:
            logger.error("Privacy proxy: request to agent failed: %s", exc)
            return JSONResponse(
                status_code=502,
                content={"detail": f"Privacy proxy: upstream agent unreachable: {exc}"},
            )

    # ── 3. Sanitize the response before returning to the MCP client ──────────
    resp_ct = resp.headers.get("content-type", "")
    safe_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }

    if "application/json" in resp_ct:
        try:
            data = resp.json()
            sanitized = sanitizer.sanitize(data)
            return JSONResponse(
                content=sanitized,
                status_code=resp.status_code,
                headers=safe_headers,
            )
        except Exception as exc:
            logger.warning("Privacy proxy: JSON sanitization failed: %s", exc)
            # Fall through to raw passthrough

    if resp_ct.startswith("text/"):
        sanitized_text = sanitizer.sanitize(resp.text)
        media_type = resp_ct.split(";")[0].strip()
        return Response(
            content=sanitized_text.encode("utf-8", errors="replace"),
            status_code=resp.status_code,
            headers=safe_headers,
            media_type=media_type,
        )

    # Binary / unknown content – pass through unchanged
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=safe_headers,
        media_type=resp_ct or None,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _restore_body(raw: bytes, content_type: str) -> bytes:
    """Restore tokens in a request body before forwarding to the agent."""
    if not raw:
        return raw
    if "application/json" in content_type:
        try:
            data = json.loads(raw)
            restored = sanitizer.restore(data)
            return json.dumps(restored).encode("utf-8")
        except (json.JSONDecodeError, Exception):
            pass  # fall through to text handling
    if content_type.startswith("text/"):
        return sanitizer.restore(raw.decode("utf-8", errors="replace")).encode("utf-8")
    return raw
