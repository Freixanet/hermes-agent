"""QR device-pairing between this dashboard and the Alice iOS app.

The dashboard is the Mac side of the v1 handshake documented in Alice's
``docs/pairing.md``: it mints a short-lived ``alice://pair`` deep link, the
operator shows it as a QR code, and the phone exchanges the bearer token
exactly once for gateway + optional dashboard credentials.

Pairing always targets the installation's MAIN profile — the one
``profiles.list`` reports as ``is_default`` (the HERMES_HOME root; the
profiles the operator calls "bots" are named profiles). The dashboard's
selected profile and the sticky active profile never decide who Alice is.
When the main profile has no running gateway, the session endpoint
provisions one idempotently: missing ``API_SERVER_KEY``/``API_SERVER_PORT``/
``API_SERVER_HOST`` are created in the profile's ``.env``; the long-lived key
is preserved and stale host/port values are reconciled only while that gateway
is stopped. Hermes' own launchd lifecycle starts the main gateway, and a
localhost-bound listener is published inside the tailnet through Tailscale
Serve. Named-profile gateways are never stopped or rewritten by pairing.

Nothing about the offer is persisted. Offers live only in this process;
restarting the dashboard invalidates every outstanding code. The QR contains
only the short-lived claim token, never Hermes' long-lived credentials.

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
import contextlib
import http.client
import ipaddress
import json
import logging
import re
import secrets
import socket
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
from hermes_cli.web_deps import LateState, late
from hermes_cli.web_routers._common import http_failure

_log = logging.getLogger("hermes_cli.web_server")
router = APIRouter()

# Late-bound so tests and the dashboard's owning modules remain the authority.
_require_token = late("_require_token")
load_config = late("load_config", "hermes_cli.config")
cfg_get = late("cfg_get", "hermes_cli.config")
get_env_value_prefer_dotenv = late("get_env_value_prefer_dotenv", "hermes_cli.config")
save_env_value = late("save_env_value", "hermes_cli.config")
list_profiles = late("list_profiles", "hermes_cli.profiles")
launchd_start = late("launchd_start", "hermes_cli.gateway")
save_config = late("save_config", "hermes_cli.config")
_CONFIG_MUTATION_LOCK = LateState("_CONFIG_MUTATION_LOCK")

OFFER_TTL_SECONDS = 300
MAX_PENDING_OFFERS = 256
MAX_PENDING_PER_IP = 8
CLAIM_BODY_MAX_BYTES = 4096
CLAIM_RATE_MAX_PER_WINDOW = 30
CLAIM_RATE_WINDOW_SEC = 60.0
# Candidate ports for a freshly provisioned main-profile gateway. The first
# one that actually binds on 127.0.0.1 wins and is persisted in the profile's
# .env; 8642 is deliberately absent because bot-profile gateways claim it.
MAIN_GATEWAY_PORT_CANDIDATES = range(8643, 8670)

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
        data = json.loads(proc.stdout)
    except ValueError:
        return None
    ips = data.get("Self", {}).get("TailscaleIPs") or []
    return next((ip for ip in ips if _is_ipv4(ip)), None)


def _tailscale_dns_name() -> Optional[str]:
    """This Mac's MagicDNS name (``machine.tailnet.ts.net``), the stable
    tailnet hostname — preferable to advertising a raw IP."""
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
        name = json.loads(proc.stdout).get("Self", {}).get("DNSName") or ""
    except ValueError:
        return None
    return name.rstrip(".").strip() or None


def _pairing_setting(request: Request, key: str, default: Any) -> Any:
    del request  # global dashboard setting; retained in signature for test seams
    try:
        config = load_config()
    except Exception:  # noqa: BLE001 — config trouble must not kill the route
        return default
    return cfg_get(config, "dashboard", "alice_pairing", key, default=default)


@contextlib.contextmanager
def _main_profile_scope(profile: str):
    """Pin Hermes' profile-aware helpers to the main profile's home.

    The dashboard process inherits the sticky ACTIVE profile as its implicit
    scope, so plain ``save_env_value`` / ``load_env`` / gateway-service
    suffixes would resolve to whichever bot is currently active — exactly the
    profile this feature must never touch. Inside this block every
    home-derived resolution (env path, launchd plist, credential reads)
    points at the main profile's HERMES_HOME (the installation root).
    """
    from hermes_cli.profiles import get_profile_dir
    from hermes_constants import (
        reset_hermes_home_override,
        set_hermes_home_override,
    )

    token = set_hermes_home_override(get_profile_dir(profile))
    try:
        yield
    finally:
        reset_hermes_home_override(token)


def _resolve_main_profile() -> Tuple[str, str]:
    """Resolve the installation's MAIN profile — the one Alice's Home chat
    talks to.

    The canonical rule is ``profiles.list``'s own ``is_default`` flag: the
    HERMES_HOME root profile, display name from its ``profile.yaml``. The
    dashboard's currently-selected profile and the sticky active profile both
    follow the operator's current bot and must never decide who Alice is.
    """
    profiles = [p for p in (list_profiles() or []) if getattr(p, "is_default", False)]
    if not profiles:
        raise HTTPException(
            status_code=503,
            detail=(
                "No default Hermes profile was found on this installation, so "
                "there is no main agent for Alice to pair with."
            ),
        )
    main = profiles[0]
    return main.name, (getattr(main, "display_name", "") or "").strip()


def _main_gateway_running(profile: str) -> bool:
    """Whether the main profile's gateway is alive, per the same runtime
    checks (pid file / state file) the rest of Hermes uses."""
    return any(
        getattr(p, "name", None) == profile and getattr(p, "gateway_running", False)
        for p in (list_profiles() or [])
    )


def _allocate_gateway_port() -> int:
    """First localhost port from the candidate range that is actually free."""
    for port in MAIN_GATEWAY_PORT_CANDIDATES:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
    raise HTTPException(
        status_code=503,
        detail=(
            "No free local port was available for the main Hermes gateway "
            f"({MAIN_GATEWAY_PORT_CANDIDATES.start}-{MAIN_GATEWAY_PORT_CANDIDATES.stop - 1})."
        ),
    )


def _port_bindable(address: str, port: int) -> bool:
    """Whether a server could actually bind (address, port) right now."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((address, port))
        return True
    except OSError:
        return False


def _provision_main_gateway_env(
    env: Dict[str, str], *, gateway_running: bool = False
) -> Dict[str, str]:
    """Create or reconcile the main-gateway settings in the profile's
    ``.env``. A live gateway is immutable here: changing its key, host or port
    underneath the process would make the QR disagree with the listener. When
    the main gateway is stopped, missing values are created and stale host/port
    values are reconciled before it starts. Returns exactly what was written.
    """
    if gateway_running:
        return {}

    writes: Dict[str, str] = {}
    if not (env.get("API_SERVER_KEY") or "").strip():
        writes["API_SERVER_KEY"] = secrets.token_urlsafe(48)

    host = (env.get("API_SERVER_HOST") or "").strip().strip("[]").lower()
    # Exposure is Tailscale Serve's job; a direct bind to a routable address
    # (often a stale, hardcoded tailnet IP) would bypass the tailnet-only
    # path this feature promises.
    if host not in {"127.0.0.1", "localhost", "0.0.0.0", "::"}:
        if host:
            _log.info(
                "alice pairing: replacing non-local API_SERVER_HOST %r with 127.0.0.1",
                host,
            )
        writes["API_SERVER_HOST"] = "127.0.0.1"
        host = "127.0.0.1"
    elif not host:
        writes["API_SERVER_HOST"] = "127.0.0.1"
        host = "127.0.0.1"

    port = _valid_port(env.get("API_SERVER_PORT"))
    if port is None or not _port_bindable(host, port):
        if port is not None:
            _log.info(
                "alice pairing: API_SERVER_PORT %s is not bindable; allocating a free one",
                port,
            )
        writes["API_SERVER_PORT"] = str(_allocate_gateway_port())

    for key, value in writes.items():
        save_env_value(key, value)
        # The name is safe to log; the value never is.
        _log.info("alice pairing: provisioned %s for the main gateway", key)
    return writes


def _set_dashboard_key(key: str, value: Any) -> None:
    """Write one ``dashboard.<key>`` config value under the same mutation
    lock every dashboard config route uses."""
    with _CONFIG_MUTATION_LOCK:
        config = load_config()
        dashboard = config.get("dashboard")
        if not isinstance(dashboard, dict):
            dashboard = {}
            config["dashboard"] = dashboard
        dashboard[key] = value
        save_config(config)


def _start_main_gateway(profile: str) -> None:
    """Start only the installation's main profile through Hermes' own
    profile-scoped launchd lifecycle.

    Named-profile gateways are independent siblings (the normal Hermes
    multi-profile topology), so pairing must never stop, unload or rewrite
    them. ``launchd_start`` self-heals a missing/stale plist and uses Hermes'
    macOS detached fallback only when launchd itself is unavailable. The
    caller verifies the resulting socket and authenticated API before minting
    a QR, so a failed fallback cannot produce a usable offer.
    """
    try:
        launchd_start()
    except SystemExit as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Could not start the main Hermes gateway for profile '{profile}'.",
        ) from exc


def _await_gateway_socket(address: str, port: int, timeout: float = 90.0) -> None:
    """Wait for a freshly started gateway to accept TCP connections before
    the authoritative authenticated probe runs. Plugin discovery makes cold
    boots slow; a refused socket is retried until the deadline."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection((address, port), timeout=2.0):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "The main Hermes gateway did not become reachable after "
                        "being started. Check its launchd logs and try again."
                    ),
                ) from None
            time.sleep(1.0)


def _ensure_tailscale_forward(port: int) -> None:
    """Publish a localhost-bound gateway inside the tailnet, idempotently.

    Only the forward for THIS port is touched: existing forwards (including
    any other service's) and funnel settings are left alone. A stale entry on
    the same listen port converges to the gateway's own target, since that
    port belongs to the gateway we just provisioned.
    """
    current = _tailscale_tcp_forward_target(port)
    if current and current.lower().removeprefix("tcp://") in {
        f"127.0.0.1:{port}",
        f"localhost:{port}",
    }:
        return
    result = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [
            "tailscale",
            "serve",
            "--bg",
            "--yes",
            "--tcp",
            str(port),
            f"tcp://127.0.0.1:{port}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise HTTPException(
            status_code=503,
            detail=(
                "Tailscale Serve could not publish the gateway port "
                f"{port} inside the tailnet{(': ' + result.stderr.strip()) if result.stderr.strip() else '.'} "
                "Without it, the iPhone cannot reach a localhost-bound gateway."
            ),
        )
    _log.info("alice pairing: tailscale serve tcp forward ensured on port %s", port)


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


def _dashboard_reachable_on(address: str, bound_host: Any, bound_port: int) -> bool:
    """The claim URL must be reachable directly on the host Alice is given.

    A wildcard bind is reachable everywhere; a matching bind is trivially so.
    A loopback-bound dashboard is also reachable when Tailscale Serve
    publishes this exact port back to loopback — the documented setup
    (``tailscale serve --tcp <port> tcp://127.0.0.1:<port>``), in which the
    tailnet path is Serve's and the dashboard never needs a routable bind.
    """
    bound = str(bound_host or "127.0.0.1").strip().strip("[]").rstrip(".").lower()
    advertised = address.rstrip(".").lower()
    if bound in {"0.0.0.0", "::"} or bound == advertised:
        return True
    if bound in {"127.0.0.1", "localhost", ""}:
        target = _tailscale_tcp_forward_target(bound_port)
        if target and target.lower().removeprefix("tcp://") in {
            f"127.0.0.1:{bound_port}",
            f"localhost:{bound_port}",
        }:
            return True
    return False


def _valid_port(raw: Any) -> Optional[int]:
    try:
        port = int(raw)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _tailscale_tcp_forward_target(port: int) -> Optional[str]:
    """Return the local target of a Tailscale Serve TCP forward, if configured."""
    try:
        result = subprocess.run(
            ["tailscale", "serve", "status", "--json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return None

    tcp = payload.get("TCP")
    if not isinstance(tcp, dict):
        return None

    rule = tcp.get(str(port))
    if not isinstance(rule, dict):
        return None

    target = rule.get("TCPForward")
    if not isinstance(target, str) or not target.strip():
        return None

    return target.strip()


def _gateway_probe_address(
    advertised_address: str, port: int, env: Dict[str, str]
) -> str:
    """Probe localhost when Tailscale Serve publishes the local gateway."""
    bound = (env.get("API_SERVER_HOST") or "").strip().strip("[]").lower()

    if bound in {"127.0.0.1", "localhost"}:
        target = _tailscale_tcp_forward_target(port)
        if target:
            normalized = target.lower().removeprefix("tcp://")
            if normalized in {f"127.0.0.1:{port}", f"localhost:{port}"}:
                return "127.0.0.1"

    return advertised_address


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
) -> Tuple[Dict[str, Any], str, str, str]:
    """Assemble and validate exactly the configuration Alice will receive.

    Always targets the installation's MAIN profile, and provisions its
    gateway when the installation does not run one yet: missing gateway
    settings are created, the launchd service is installed and started
    (idempotently, never restarting a live gateway), and a localhost-bound
    gateway is published inside the tailnet through Tailscale Serve.
    """
    profile, display_name = await asyncio.to_thread(_resolve_main_profile)
    with _main_profile_scope(profile):
        config, address = await _build_main_profile_config(request, profile)
    if display_name:
        config["profile_display_name"] = display_name
    return config, profile, address, display_name


async def _build_main_profile_config(
    request: Request, profile: str
) -> Tuple[Dict[str, Any], str]:
    """The provisioning sequence, run inside the main profile's scope."""
    env = await asyncio.to_thread(_read_profile_env, profile)
    gateway_running = await asyncio.to_thread(_main_gateway_running, profile)
    writes = await asyncio.to_thread(
        _provision_main_gateway_env, env, gateway_running=gateway_running
    )
    env = {**env, **writes}

    key = env.get("API_SERVER_KEY")
    if not key:
        raise HTTPException(
            status_code=503,
            detail=(
                f"The main profile '{profile}' has no gateway key "
                "(API_SERVER_KEY in its .env) and it could not be provisioned."
            ),
        )
    gateway_port = _valid_port(env.get("API_SERVER_PORT") or 8642)
    if gateway_port is None:
        raise HTTPException(status_code=503, detail="The Hermes gateway port is invalid.")

    if not gateway_running:
        await asyncio.to_thread(_start_main_gateway, profile)

    configured_address = _pairing_setting(request, "address", None)
    # Prefer the MagicDNS name (stable across addresses) over a raw IP.
    raw_address = (
        configured_address
        or await asyncio.to_thread(_tailscale_dns_name)
        or await asyncio.to_thread(_tailscale_ipv4)
    )
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
    normalized_dashboard_host = str(bound_host or "").strip().strip("[]").lower()
    if normalized_dashboard_host in {"127.0.0.1", "localhost", ""}:
        await asyncio.to_thread(_ensure_tailscale_forward, bound_port)
    if not await asyncio.to_thread(
        _dashboard_reachable_on, address, bound_host, bound_port
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "The dashboard is not reachable through the tailnet address "
                "that would be placed in the pairing code."
            ),
        )
    # Alice's dashboard login sends the advertised address as its Host header,
    # and the dashboard's anti-rebinding check accepts exactly the configured
    # public hostname. Record it once; never overwrite an operator value.
    if not (cfg_get(load_config(), "dashboard", "public_url", default="") or "").strip():
        _set_dashboard_key("public_url", f"http://{address}:{bound_port}")

    # A localhost-bound gateway is only reachable from the phone through a
    # Tailscale Serve TCP forward; make sure it exists before probing.
    bound = (env.get("API_SERVER_HOST") or "").strip().strip("[]").lower()
    if bound in {"127.0.0.1", "localhost", ""}:
        await asyncio.to_thread(_ensure_tailscale_forward, gateway_port)

    probe_address = _gateway_probe_address(address, gateway_port, env)
    if not await asyncio.to_thread(_main_gateway_running, profile):
        await asyncio.to_thread(_await_gateway_socket, probe_address, gateway_port)
    await asyncio.to_thread(_probe_gateway, probe_address, gateway_port, key)

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
    return config, address


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
        config, profile, address, display_name = await _build_pairing_config(request)

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
            "profile_display_name": display_name,
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
