"""QR device-pairing between this dashboard and the Alice iOS app.

The dashboard is the Mac side of the v1 handshake documented in Alice's
``docs/pairing.md``: it mints a short-lived ``alice://pair`` deep link, the
operator shows it as a QR code, and the phone exchanges the bearer token
exactly once for gateway + optional dashboard credentials.

Nothing is persisted. Offers live only in this process; restarting the
dashboard invalidates every outstanding code. The QR contains only the
short-lived claim token, never Hermes' long-lived credentials.

Routes:

  POST /api/alice/pairing/session  authenticated; returns one QR payload.
  POST /api/alice/pairing/claim    public by path, but protected by a one-time
                                   token plus loopback/tailnet source gating.

V1 deliberately has no HMAC field. Alice cannot verify an HMAC whose key is
known only to this Mac, so adding one would make the wire format incompatible
without adding client-verifiable authenticity.
"""
from __future__ import annotations

import asyncio
import base64
import http.client
import ipaddress
import json
import logging
import re
import secrets
import subprocess
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Tuple

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.web_deps import late
from hermes_cli.web_routers._common import http_failure

_log = logging.getLogger("hermes_cli.web_server")
router = APIRouter()

# Late-bound so tests and the dashboard's owning modules remain the authority.
_require_token = late("_require_token")
load_config = late("load_config", "hermes_cli.config")
cfg_get = late("cfg_get", "hermes_cli.config")
get_env_value_prefer_dotenv = late("get_env_value_prefer_dotenv", "hermes_cli.config")
get_active_profile = late("get_active_profile", "hermes_cli.profiles")
normalize_profile_name = late("normalize_profile_name", "hermes_cli.profiles")
validate_profile_name = late("validate_profile_name", "hermes_cli.profiles")
profile_exists = late("profile_exists", "hermes_cli.profiles")

OFFER_TTL_SECONDS = 300
MAX_PENDING_OFFERS = 256
MAX_PENDING_PER_IP = 8
CLAIM_BODY_MAX_BYTES = 4096
CLAIM_RATE_MAX_PER_WINDOW = 30
CLAIM_RATE_WINDOW_SEC = 60.0

_lock = threading.Lock()
# token -> {expires_at, config?, used, ip, profile, created_at}
_offers: Dict[str, Dict[str, Any]] = {}
_claim_attempts: Dict[str, Deque[float]] = defaultdict(deque)
_claim_attempts_lock = threading.Lock()


# --- Protocol: exact Alice v1 envelope -------------------------------------

def _b64url(data: bytes) -> str:
    """RFC 4648 §5 without padding, matching Alice's strict parser."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical_offer_bytes(offer: Dict[str, Any]) -> bytes:
    """Emit the fixed v1 key order used by the Alice helper and docs."""
    payload: Dict[str, Any] = {"c": offer["c"], "t": offer["t"], "e": offer["e"]}
    if offer.get("pr"):
        payload["pr"] = offer["pr"]
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _build_pairing_link(offer: Dict[str, Any]) -> str:
    return f"alice://pair?v=1&p={_b64url(_canonical_offer_bytes(offer))}"


# --- Configuration the offer hands over -----------------------------------

def _read_profile_env(profile: str) -> Dict[str, str]:
    """Read only the selected profile's ``.env`` gateway values."""
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
    """Return this Mac's Tailscale IPv4; never fall back to raw IPv6 in v1."""
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
    return next((ip for ip in ips if _is_ipv4(ip)), None)


def _pairing_setting(request: Request, key: str, default: Any) -> Any:
    del request  # global dashboard setting; retained in signature for test seams
    try:
        config = load_config()
    except Exception:  # noqa: BLE001 — config trouble must not kill the route
        return default
    return cfg_get(config, "dashboard", "alice_pairing", key, default=default)


def _selected_profile(request: Request) -> str:
    """Use the dashboard's explicit management profile when supplied."""
    requested = request.query_params.get("profile")
    if not requested:
        return get_active_profile() or "default"
    try:
        profile = normalize_profile_name(requested)
        validate_profile_name(profile)
    except Exception as exc:  # noqa: BLE001 — ingress validation fails closed
        raise HTTPException(status_code=400, detail="Invalid Hermes profile") from exc
    if not profile_exists(profile):
        raise HTTPException(status_code=404, detail="Hermes profile not found")
    return profile


def _is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _validated_advertised_host(raw: Any) -> Optional[str]:
    """Accept one IPv4 or DNS hostname suitable for ``http://host:port``."""
    value = str(raw or "").strip().rstrip(".")
    if not value or len(value) > 253 or any(ch.isspace() for ch in value):
        return None
    if "/" in value or ":" in value or "@" in value:
        return None
    if _is_ipv4(value):
        address = ipaddress.ip_address(value)
        return None if address.is_loopback or address.is_unspecified else value
    if value.lower() == "localhost":
        return None
    # A dotted-numeric value that is not a real IPv4 is not a hostname fallback.
    if all(ch.isdigit() or ch == "." for ch in value):
        return None
    labels = value.split(".")
    if any(not label or not _HOST_LABEL.fullmatch(label) for label in labels):
        return None
    return value


def _source_ip(request: Request) -> str:
    """Use the actual peer, never a client-controlled forwarded header."""
    return request.client.host if request.client else ""


def _origin_allowed(ip: str) -> bool:
    """V1 claims are accepted only from loopback or Tailscale IPv4 CGNAT."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        if ip.lower().startswith("::ffff:"):
            try:
                address = ipaddress.ip_address(ip.split(":")[-1])
            except ValueError:
                return False
        else:
            return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback:
        return True
    return isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network(
        "100.64.0.0/10"
    )


def _dashboard_reachable_on(address: str, bound_host: Any) -> bool:
    """The claim URL must be reachable directly on the host Alice is given."""
    bound = str(bound_host or "127.0.0.1").strip().strip("[]").rstrip(".").lower()
    advertised = address.rstrip(".").lower()
    return bound in {"0.0.0.0", "::"} or bound == advertised


def _valid_port(raw: Any) -> Optional[int]:
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _probe_gateway(address: str, port: int, key: str) -> None:
    """Probe the exact host/port Alice will use, without following redirects."""
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {key}",
        "X-Hermes-Session-Token": key,
    }
    statuses: list[str] = []
    last_error: Optional[Exception] = None
    for route in ("/v1/capabilities", "/v1/models"):
        conn = http.client.HTTPConnection(address, port, timeout=6)
        try:
            conn.request("GET", route, headers=headers)
            response = conn.getresponse()
            status = response.status
            response.read(1024)
            statuses.append(f"{route}: {status}")
            if 200 <= status < 300:
                return
            if status in (401, 403):
                raise HTTPException(
                    status_code=503,
                    detail="The Hermes gateway rejected its configured API key.",
                )
        except HTTPException:
            raise
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            conn.close()
    detail = ", ".join(statuses)
    suffix = f" ({detail})" if detail else ""
    raise HTTPException(
        status_code=503,
        detail=(
            f"The Hermes gateway is not reachable at the address Alice would use{suffix}. "
            "Bind the API server to the Tailscale-reachable interface and try again."
        ),
    ) from last_error


def _has_forwarding_headers(request: Request) -> bool:
    """V1's source gate is direct-connect only; never trust proxy-supplied peers."""
    return any(
        request.headers.get(name)
        for name in ("forwarded", "x-forwarded-for", "x-real-ip")
    )


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
    with _lock:
        _offers.clear()
    with _claim_attempts_lock:
        _claim_attempts.clear()


async def _build_pairing_config(
    request: Request,
) -> Tuple[Dict[str, Any], str, str]:
    """Assemble and validate exactly the configuration Alice will receive."""
    profile = _selected_profile(request)
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
    gateway_port = _valid_port(env.get("API_SERVER_PORT") or 8642)
    if gateway_port is None:
        raise HTTPException(status_code=503, detail="The Hermes gateway port is invalid.")

    configured_address = _pairing_setting(request, "address", None)
    raw_address = configured_address or await asyncio.to_thread(_tailscale_ipv4)
    address = _validated_advertised_host(raw_address)
    if not address:
        raise HTTPException(
            status_code=503,
            detail=(
                "Could not determine a safe address to advertise. Install Tailscale, "
                "or set dashboard.alice_pairing.address to an IPv4/hostname reachable "
                "through the tailnet."
            ),
        )

    bound_port = _valid_port(getattr(request.app.state, "bound_port", 9119))
    if bound_port is None:
        raise HTTPException(status_code=503, detail="The dashboard port is invalid.")
    bound_host = getattr(request.app.state, "bound_host", "127.0.0.1")
    if not _dashboard_reachable_on(address, bound_host):
        raise HTTPException(
            status_code=503,
            detail=(
                "The dashboard is bound to a local-only address, so this iPhone cannot "
                "reach the pairing claim endpoint. Bind the dashboard to the Tailscale-"
                "reachable interface (for example 0.0.0.0 with dashboard auth enabled)."
            ),
        )

    await asyncio.to_thread(_probe_gateway, address, gateway_port, key)

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
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=512)
    device_name: Optional[str] = Field(default=None, max_length=256)


_NO_STORE = {"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"}


def _sanitize_device_name(raw: Optional[str]) -> str:
    if not raw or not raw.strip():
        return "iPhone"
    cleaned = "".join(
        ch for ch in raw.strip() if (code := ord(ch)) >= 32 and code != 127
    )
    return cleaned[:64] or "iPhone"


def _tombstone(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only replay/expiry metadata after credentials are no longer needed."""
    return {
        "expires_at": entry["expires_at"],
        "used": True,
        "ip": entry["ip"],
        "profile": entry["profile"],
        "created_at": entry["created_at"],
    }


def _gc_offers_locked(now: float) -> None:
    for token in [t for t, entry in _offers.items() if entry["expires_at"] <= now]:
        del _offers[token]


async def _read_body_limited(request: Request, limit: int) -> Optional[bytes]:
    """Read a request body without ever buffering more than ``limit`` bytes."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/api/alice/pairing/session")
async def create_pairing_session(request: Request) -> JSONResponse:
    """Mint one authenticated, short-lived Alice v1 pairing offer."""
    try:
        _require_token(request)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 — late-bound seam, same contract as callers
        _log.exception("alice pairing: session token check failed")
        raise HTTPException(status_code=401, detail="Not authenticated") from None

    with http_failure(
        "alice pairing: config assembly failed",
        503,
        detail="Could not assemble the pairing configuration.",
    ):
        config, profile, address = await _build_pairing_config(request)

    token = secrets.token_urlsafe(24)
    now = time.time()
    # One integer boundary is shared by the QR and the in-memory store.
    expires_at = int(now) + OFFER_TTL_SECONDS
    bound_port = _valid_port(getattr(request.app.state, "bound_port", 9119))
    if bound_port is None:
        raise HTTPException(status_code=503, detail="The dashboard port is invalid.")
    offer = {
        "c": f"http://{address}:{bound_port}/api/alice/pairing/claim",
        "t": token,
        "e": expires_at,
        "pr": profile,
    }
    link = _build_pairing_link(offer)

    ip = _source_ip(request)
    with _lock:
        _gc_offers_locked(now)

        # One live QR per dashboard peer + Hermes profile. "New code" really
        # replaces the previous code instead of silently leaving both valid.
        for old_token, entry in list(_offers.items()):
            if not entry["used"] and entry["ip"] == ip and entry["profile"] == profile:
                del _offers[old_token]

        pending_for_ip = sum(
            1 for entry in _offers.values() if entry["ip"] == ip and not entry["used"]
        )
        if pending_for_ip >= MAX_PENDING_PER_IP:
            raise HTTPException(
                status_code=429,
                detail="Too many pending pairing codes. Use one or let it expire.",
            )
        if len(_offers) >= MAX_PENDING_OFFERS:
            raise HTTPException(
                status_code=429,
                detail="Too many pairing sessions are pending. Let an old code expire.",
            )
        _offers[token] = {
            "expires_at": expires_at,
            "config": config,
            "used": False,
            "ip": ip,
            "profile": profile,
            "created_at": now,
        }

    audit_log(AuditEvent.PAIRING_SESSION_CREATED, ip=ip, profile=profile)
    _log.info("alice pairing: session created (profile=%s)", profile)
    from datetime import datetime, timezone

    return JSONResponse(
        {
            "payload": link,
            "profile": profile,
            "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat(),
        },
        headers=_NO_STORE,
    )


@router.post("/api/alice/pairing/claim")
async def claim_pairing(request: Request) -> JSONResponse:
    """Exchange the QR bearer exactly once for long-lived configuration."""
    ip = _source_ip(request)
    if _has_forwarding_headers(request) or not _origin_allowed(ip):
        audit_log(AuditEvent.PAIRING_CLAIM_REJECTED, ip=ip, reason="origin")
        return JSONResponse({"error": "forbidden"}, status_code=403, headers=_NO_STORE)
    if _claim_rate_limited(ip):
        audit_log(AuditEvent.PAIRING_CLAIM_REJECTED, ip=ip, reason="rate_limited")
        return JSONResponse(
            {"error": "rate_limited"}, status_code=429, headers=_NO_STORE
        )

    body = await _read_body_limited(request, CLAIM_BODY_MAX_BYTES)
    if body is None:
        return JSONResponse({"error": "unknown"}, status_code=404, headers=_NO_STORE)
    try:
        parsed = _ClaimBody.model_validate(json.loads(body))
    except Exception:  # noqa: BLE001 — no parser oracle: every bad body is unknown
        return JSONResponse({"error": "unknown"}, status_code=404, headers=_NO_STORE)

    now = time.time()
    config: Optional[Dict[str, Any]] = None
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
            config = entry.get("config")
            if config is None:
                outcome = "unknown"
            else:
                _offers[parsed.token] = _tombstone(entry)
                outcome = "ok"

    if outcome != "ok":
        audit_log(AuditEvent.PAIRING_CLAIM_REJECTED, ip=ip, reason=outcome)
        status = 410 if outcome in ("used", "expired") else 404
        return JSONResponse({"error": outcome}, status_code=status, headers=_NO_STORE)

    device_name = _sanitize_device_name(parsed.device_name)
    audit_log(AuditEvent.PAIRING_CLAIMED, ip=ip, device=device_name)
    _log.info("alice pairing: claimed by %s", device_name)
    return JSONResponse(config, headers=_NO_STORE)
