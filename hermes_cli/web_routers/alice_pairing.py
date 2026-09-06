"""QR device-pairing between this dashboard and the Alice iOS app.

The dashboard is the Mac side of the handshake documented in the Alice repo
(``docs/pairing.md``): it mints a one-time signed ``alice://pair`` deep link,
the operator shows it as a QR code, and the phone exchanges the token exactly
once for the connection configuration — gateway URL + key, dashboard URL +
login. Nothing is persisted: the offer store is in memory, so a dashboard
restart invalidates every code it ever showed, which is the safe direction to
fail in. No token, key or credential is ever logged.

Two routes:

  POST /api/alice/pairing/session  authenticated (dashboard session token);
                                   returns the deep link to render as a QR.
  POST /api/alice/pairing/claim    public (allowlisted in
                                   ``dashboard_auth.public_paths``); carries
                                   its own one-time token — that token, not
                                   the allowlist, is the security boundary,
                                   exactly like ``/api/cron/fire``.

The claim is additionally gated to the tailnet (``100.64.0.0/10``) plus
loopback; ``dashboard.alice_pairing.allow_lan`` relaxes that, and
``dashboard.alice_pairing.address`` overrides the advertised address.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import subprocess
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Tuple

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.web_deps import late
from hermes_cli.web_routers._common import http_failure

_log = logging.getLogger("hermes_cli.web_server")
router = APIRouter()

# Late-bound so a test's monkeypatch on the owning module wins at call time.
_require_token = late("_require_token")
load_config = late("load_config", "hermes_cli.config")
cfg_get = late("cfg_get", "hermes_cli.config")
get_env_value_prefer_dotenv = late("get_env_value_prefer_dotenv", "hermes_cli.config")
get_active_profile = late("get_active_profile", "hermes_cli.profiles")

OFFER_TTL_SECONDS = 300
MAX_PENDING_OFFERS = 256
MAX_PENDING_PER_IP = 8
CLAIM_BODY_MAX_BYTES = 4096
CLAIM_RATE_MAX_PER_WINDOW = 30
CLAIM_RATE_WINDOW_SEC = 60.0

_lock = threading.Lock()
# token -> {"expires_at", "config", "used", "ip", "created_at"}
_offers: Dict[str, Dict[str, Any]] = {}
_claim_attempts: Dict[str, Deque[float]] = defaultdict(deque)
_claim_attempts_lock = threading.Lock()

#: Per-process HMAC secret: only this process verifies what this process
#: signed, so rotating it with the process is by design (a restart kills any
#: code shown before it).
_secret = secrets.token_bytes(32)


# --- Protocol: identical bytes to the helper this replaces -----------------

def _b64url(data: bytes) -> str:
    """RFC 4648 §5 without padding, matching the iOS parser's strictness."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical_offer_bytes(offer: Dict[str, Any]) -> bytes:
    """Fixed key order keeps signatures stable across re-mints."""
    payload: Dict[str, Any] = {"c": offer["c"], "t": offer["t"], "e": offer["e"]}
    if offer.get("pr"):
        payload["pr"] = offer["pr"]
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _build_pairing_link(offer: Dict[str, Any]) -> str:
    signature = hmac.new(_secret, _canonical_offer_bytes(offer), hashlib.sha256).hexdigest()
    return (
        f"alice://pair?v=1&p={_b64url(_canonical_offer_bytes(offer))}&s={signature}"
    )


def _self_verify(link: str) -> bool:
    """Round-trip guard: what we hand to the SPA must parse back and verify."""
    try:
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        payload = base64.urlsafe_b64decode(query["p"][0] + "=" * (-len(query["p"][0]) % 4))
        expected = hmac.new(_secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, query["s"][0])
    except Exception:  # noqa: BLE001 — any malformation is a refusal
        return False


# --- Configuration the offer hands over -----------------------------------

def _read_profile_env(profile: str) -> Dict[str, str]:
    """Parse the profile's ``.env`` for the gateway's ``API_SERVER_*`` values.

    ``load_env()`` is pinned to the *process* HERMES_HOME, which for the
    dashboard is the machine root, so the profile file is read directly —
    the same file the launchd gateway for that profile runs with.
    """
    from hermes_constants import get_default_hermes_root

    root = Path(get_default_hermes_root())
    env_path = root / ".env" if profile == "default" else root / "profiles" / profile / ".env"
    values: Dict[str, str] = {}
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        equals = line.find("=")
        if equals <= 0:
            continue
        key = line[:equals].strip()
        value = line[equals + 1:].strip().strip("'\"")
        if key:
            values[key] = value
    return values


def _tailscale_ipv4() -> Optional[str]:
    """The address phone and Mac share, the way ``scripts/phone.mjs`` finds it."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        ips = json.loads(proc.stdout).get("Self", {}).get("TailscaleIPs") or []
    except ValueError:
        return None
    return next((ip for ip in ips if ":" not in ip), ips[0] if ips else None)


def _pairing_setting(request: Request, key: str, default: Any) -> Any:
    try:
        config = load_config()
    except Exception:  # noqa: BLE001 — config trouble must not kill the route
        return default
    return cfg_get(config, "dashboard", "alice_pairing", key, default=default)


def _source_ip(request: Request) -> str:
    """The peer address, deliberately NOT ``client_ip()``'s first
    ``X-Forwarded-For`` hop: a client-supplied XFF header would let a
    hostile-LAN caller forge a tailnet address and walk past the source
    gate. This dashboard is reached directly, so the peer is the truth."""
    return request.client.host if request.client else ""


def _origin_allowed(ip: str, allow_lan: bool) -> bool:
    if allow_lan:
        return True
    address = ip.replace("::ffff:", "")
    if address in ("::1", "127.0.0.1"):
        return True
    parts = address.split(".")
    if len(parts) < 2:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    # CGNAT 100.64.0.0/10 — a tailnet peer.
    return first == 100 and 64 <= second <= 127


def _claim_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    cutoff = now - CLAIM_RATE_WINDOW_SEC
    with _claim_attempts_lock:
        bucket = _claim_attempts[ip or "_unknown_"]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= CLAIM_RATE_MAX_PER_WINDOW:
            return True
        bucket.append(now)
        return False


def _reset_claim_state_for_tests() -> None:
    """Test-only: drop every offer and rate-limit bucket."""
    global _secret
    with _lock:
        _offers.clear()
        _secret = secrets.token_bytes(32)
    with _claim_attempts_lock:
        _claim_attempts.clear()


async def _build_pairing_config(
    request: Request,
) -> Tuple[Dict[str, Any], str, str]:
    """Everything the phone needs, gathered from the sources the dashboard
    already owns — the profile's gateway env and the dashboard credentials.
    Raises 503 with an operator-readable reason when the address or key is
    undiscoverable; raises nothing that leaks either value. Returns the
    config, the profile name and the advertised address."""
    profile = get_active_profile() or "default"
    env = await asyncio.to_thread(_read_profile_env, profile)
    key = env.get("API_SERVER_KEY")
    if not key:
        raise HTTPException(
            status_code=503,
            detail=(
                f"No gateway key found for profile '{profile}' "
                "(API_SERVER_KEY in its .env). Start the gateway for this "
                "profile, then try again."
            ),
        )
    try:
        gateway_port = int(env.get("API_SERVER_PORT") or 8642)
    except ValueError:
        gateway_port = 8642

    address = _pairing_setting(request, "address", None) or await asyncio.to_thread(
        _tailscale_ipv4
    )
    if not address:
        raise HTTPException(
            status_code=503,
            detail=(
                "Could not determine the address to advertise. Install "
                "Tailscale, or set dashboard.alice_pairing.address in "
                "config.yaml."
            ),
        )

    bound_port = getattr(request.app.state, "bound_port", 9119)
    config: Dict[str, Any] = {
        "profile": profile,
        "gateway": {"url": f"http://{address}:{gateway_port}", "key": key},
        "dashboard": None,
    }
    username = get_env_value_prefer_dotenv("HERMES_DASHBOARD_BASIC_AUTH_USERNAME")
    password = get_env_value_prefer_dotenv("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD")
    if username and password:
        config["dashboard"] = {
            "url": f"http://{address}:{bound_port}",
            "username": username,
            "password": password,
        }
    return config, profile, address


class _ClaimBody(BaseModel):
    token: str
    device_name: Optional[str] = None


_NO_STORE = {"Cache-Control": "no-store"}


def _sanitize_device_name(raw: Optional[str]) -> str:
    if not raw or not raw.strip():
        return "iPhone"
    cleaned = "".join(
        ch for ch in raw.strip() if (code := ord(ch)) >= 32 and code != 127
    )
    return cleaned[:64] or "iPhone"


def _gc_offers_locked(now: float) -> None:
    for token in [t for t, e in _offers.items() if e["expires_at"] <= now]:
        del _offers[token]
    while len(_offers) >= MAX_PENDING_OFFERS:
        _offers.pop(next(iter(_offers)))


@router.post("/api/alice/pairing/session")
async def create_pairing_session(request: Request) -> JSONResponse:
    """Mint one offer: a signed deep link for the SPA to render as a QR."""
    try:
        _require_token(request)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 — late-bound seam, same contract as callers
        _log.exception("alice pairing: session token check failed")
        raise HTTPException(status_code=401, detail="Not authenticated") from None

    with http_failure("alice pairing: config assembly failed", 503,
                      detail="Could not assemble the pairing configuration."):
        config, profile, address = await _build_pairing_config(request)

    token = secrets.token_urlsafe(24)
    now = time.time()
    expires_at = now + OFFER_TTL_SECONDS
    bound_port = getattr(request.app.state, "bound_port", 9119)
    offer = {
        "c": f"http://{address}:{bound_port}/api/alice/pairing/claim",
        "t": token,
        "e": int(expires_at),
        "pr": profile,
    }
    link = _build_pairing_link(offer)
    if not _self_verify(link):
        _log.error("alice pairing: minted link failed self-verification")
        raise HTTPException(status_code=500, detail="Pairing link failed self-verification")

    ip = _source_ip(request)
    with _lock:
        _gc_offers_locked(now)
        pending_for_ip = sum(
            1 for e in _offers.values() if e["ip"] == ip and not e["used"]
        )
        if pending_for_ip >= MAX_PENDING_PER_IP:
            raise HTTPException(
                status_code=429,
                detail="Too many pending pairing codes. Use one or let it expire.",
            )
        _offers[token] = {
            "expires_at": expires_at,
            "config": config,
            "used": False,
            "ip": ip,
            "created_at": now,
        }

    audit_log(AuditEvent.PAIRING_SESSION_CREATED, ip=ip, profile=profile)
    _log.info("alice pairing: session created (profile=%s)", profile)
    from datetime import datetime, timezone

    return JSONResponse(
        {
            "payload": link,
            "profile": profile,
            "expires_at": datetime.fromtimestamp(
                expires_at, tz=timezone.utc
            ).isoformat(),
        },
        headers=_NO_STORE,
    )


@router.post("/api/alice/pairing/claim")
async def claim_pairing(request: Request) -> JSONResponse:
    """Exchange the QR's one-time token for the configuration. Public route;
    the offer store and the source gate are the boundary."""
    ip = _source_ip(request)
    allow_lan = bool(_pairing_setting(request, "allow_lan", False))
    if not _origin_allowed(ip, allow_lan):
        audit_log(AuditEvent.PAIRING_CLAIM_REJECTED, ip=ip, reason="origin")
        return JSONResponse({"error": "forbidden"}, status_code=403, headers=_NO_STORE)
    if _claim_rate_limited(ip):
        audit_log(AuditEvent.PAIRING_CLAIM_REJECTED, ip=ip, reason="rate_limited")
        return JSONResponse(
            {"error": "rate_limited"}, status_code=429, headers=_NO_STORE
        )

    body = await request.body()
    if len(body) > CLAIM_BODY_MAX_BYTES:
        return JSONResponse({"error": "unknown"}, status_code=404, headers=_NO_STORE)
    try:
        parsed = _ClaimBody.model_validate(json.loads(body))
    except Exception:  # noqa: BLE001 — no oracle: any bad body is "unknown"
        return JSONResponse({"error": "unknown"}, status_code=404, headers=_NO_STORE)

    now = time.time()
    with _lock:
        entry = _offers.get(parsed.token)
        if entry is None:
            outcome = "unknown"
        elif entry["used"]:
            outcome = "used"
        elif entry["expires_at"] <= now:
            del _offers[parsed.token]
            outcome = "expired"
        else:
            entry["used"] = True
            outcome = "ok"

    if outcome != "ok":
        audit_log(AuditEvent.PAIRING_CLAIM_REJECTED, ip=ip, reason=outcome)
        status = 410 if outcome in ("used", "expired") else 404
        return JSONResponse({"error": outcome}, status_code=status, headers=_NO_STORE)

    device_name = _sanitize_device_name(parsed.device_name)
    audit_log(AuditEvent.PAIRING_CLAIMED, ip=ip, device=device_name)
    _log.info("alice pairing: claimed by %s", device_name)
    return JSONResponse(entry["config"], headers=_NO_STORE)
