"""Tests for the Alice QR-pairing dashboard routes.

These tests pin Alice v1's exact deep-link envelope, the MAIN-profile
resolution rule (the installation's ``is_default`` profile — never the
dashboard's selected profile or the sticky active one), the idempotent
gateway provisioning (env + launchd + Tailscale Serve), one-time/expiry
semantics, the tailnet-only claim boundary, and the fact that long-lived
credentials disappear from the offer store after claim.

No test talks to the real network: launchd, tailscale and the gateway probe
are recorded seams, but env provisioning runs the REAL ``save_env_value``
against the sandboxed HERMES_HOME so the persisted values are what actually
gets re-read.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import time
import urllib.parse
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.profiles import ProfileInfo
from hermes_cli.web_routers import alice_pairing


SESSION_URL = "/api/alice/pairing/session"
CLAIM_URL = "/api/alice/pairing/claim"
PHONE_IP = "100.70.100.2"
LAN_IP = "192.168.1.5"
MAIN_KEY = "main-gateway-key-0123456789abcdef"


@pytest.fixture
def pairing_client():
    alice_pairing._reset_claim_state_for_tests()
    prev_required = getattr(web_server.app.state, "auth_required", None)
    prev_port = getattr(web_server.app.state, "bound_port", None)
    prev_host = getattr(web_server.app.state, "bound_host", None)
    web_server.app.state.auth_required = False
    web_server.app.state.bound_port = 9119
    web_server.app.state.bound_host = "0.0.0.0"
    yield TestClient(
        web_server.app, base_url="http://testserver", client=(PHONE_IP, 50000)
    )
    web_server.app.state.auth_required = prev_required
    web_server.app.state.bound_port = prev_port
    web_server.app.state.bound_host = prev_host
    alice_pairing._reset_claim_state_for_tests()


def _client_from(ip: str) -> TestClient:
    return TestClient(web_server.app, base_url="http://testserver", client=(ip, 50000))


def _fake_profiles(home: Path, *, main_running: bool):
    """The installation under test: main profile 'default' (Alice) plus the
    radar-ia bot, whose gateway is the one that happens to be running."""
    return [
        ProfileInfo(
            name="default",
            path=home,
            is_default=True,
            gateway_running=main_running,
            display_name="Alice",
        ),
        ProfileInfo(
            name="radar-ia",
            path=home / "profiles" / "radar-ia",
            is_default=False,
            gateway_running=True,
        ),
    ]


@pytest.fixture
def main_installation(monkeypatch):
    """Provisioned installation: root .env carries the main gateway settings;
    the sticky active profile is the radar-ia BOT (pairing must ignore it)."""
    home = Path(os.environ["HERMES_HOME"])
    (home / "profiles" / "radar-ia").mkdir(parents=True, exist_ok=True)
    (home / "profiles" / "radar-ia" / ".env").write_text(
        "API_SERVER_PORT=8642\nAPI_SERVER_KEY=bot-gateway-key-radar-ia\n",
        encoding="utf-8",
    )
    (home / ".env").write_text(
        "API_SERVER_HOST=127.0.0.1\n"
        "API_SERVER_PORT=8643\n"
        f"API_SERVER_KEY={MAIN_KEY}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        alice_pairing, "list_profiles", lambda: _fake_profiles(home, main_running=True)
    )
    monkeypatch.setattr("hermes_cli.profiles.get_active_profile", lambda: "radar-ia")
    monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
    monkeypatch.setattr(alice_pairing, "_tailscale_dns_name", lambda: None)
    monkeypatch.setattr(alice_pairing, "_probe_gateway", lambda address, port, key: None)
    # The configured port must read as bindable regardless of what this
    # development machine is running at the moment.
    monkeypatch.setattr(alice_pairing, "_port_bindable", lambda address, port: True)
    return home


@pytest.fixture
def automation(monkeypatch):
    """Record launchd + Tailscale side effects without touching the host."""
    calls = {"start": 0, "serve": [], "forwards": {}}

    monkeypatch.setattr(
        alice_pairing,
        "launchd_start",
        lambda: calls.__setitem__("start", calls["start"] + 1),
    )

    def fake_serve_run(argv, **kwargs):
        calls["serve"].append(list(argv))
        if len(argv) >= 7 and argv[:2] == ["tailscale", "serve"] and "--tcp" in argv:
            port = int(argv[argv.index("--tcp") + 1])
            calls["forwards"][port] = argv[-1]
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(alice_pairing.subprocess, "run", fake_serve_run)
    monkeypatch.setattr(
        alice_pairing,
        "_tailscale_tcp_forward_target",
        lambda port: calls["forwards"].get(port),
    )
    monkeypatch.setattr(alice_pairing, "_await_gateway_socket", lambda address, port, timeout=90.0: None)
    monkeypatch.setattr(alice_pairing, "_allocate_gateway_port", lambda: 8643)
    return calls


def _session_headers():
    return {"X-Hermes-Session-Token": web_server._SESSION_TOKEN}


def _mint(client: TestClient) -> dict:
    resp = client.post(SESSION_URL, headers=_session_headers())
    assert resp.status_code == 200, resp.text
    return resp.json()


def _offer_of(payload: str) -> dict:
    query = urllib.parse.parse_qs(urllib.parse.urlparse(payload).query)
    padded = query["p"][0] + "=" * (-len(query["p"][0]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# ---------------------------------------------------------------------------
# Main-profile resolution — the architectural rule under test
# ---------------------------------------------------------------------------


class TestMainProfileResolution:
    def test_active_bot_profile_does_not_become_alice(
        self, pairing_client, main_installation
    ):
        """The sticky active profile is radar-ia (a bot): pairing must still
        deliver the installation's main profile."""
        body = _mint(pairing_client)
        assert body["profile"] == "default"
        assert body["profile_display_name"] == "Alice"
        assert _offer_of(body["payload"])["pr"] == "default"

    def test_dashboard_selected_profile_is_ignored(
        self, pairing_client, main_installation
    ):
        """A dashboard left on a bot profile (or any ?profile= value) must not
        decide who Alice pairs with; the parameter is ignored, not honoured."""
        resp = pairing_client.post(
            f"{SESSION_URL}?profile=radar-ia", headers=_session_headers()
        )
        assert resp.status_code == 200
        assert resp.json()["profile"] == "default"
        resp = pairing_client.post(
            f"{SESSION_URL}?profile=does-not-exist", headers=_session_headers()
        )
        assert resp.status_code == 200
        assert resp.json()["profile"] == "default"

    def test_claim_returns_main_profile_config(self, pairing_client, main_installation):
        token = _offer_of(_mint(pairing_client)["payload"])["t"]
        resp = pairing_client.post(CLAIM_URL, json={"token": token, "device_name": "iPhone"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["profile"] == "default"
        assert body["profile_display_name"] == "Alice"
        assert body["gateway"] == {
            "url": "http://100.67.213.42:8643",
            "key": MAIN_KEY,
        }

    def test_installation_without_default_profile_is_503(
        self, pairing_client, main_installation, monkeypatch
    ):
        monkeypatch.setattr(alice_pairing, "list_profiles", lambda: [])
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503
        assert "default" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Protocol shape — what the phone parses
# ---------------------------------------------------------------------------


class TestProtocolShape:
    def test_link_is_exact_alice_v1_shape(self, pairing_client, main_installation):
        payload = _mint(pairing_client)["payload"]
        parsed = urllib.parse.urlparse(payload)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        assert parsed.scheme == "alice"
        assert parsed.netloc == "pair"
        assert [key for key, _ in pairs] == ["v", "p"]
        assert dict(pairs)["v"] == "1"
        assert "&s=" not in payload

        offer = _offer_of(payload)
        assert list(offer) == ["c", "t", "e", "pr"]
        assert offer["pr"] == "default"
        assert offer["c"] == "http://100.67.213.42:9119/api/alice/pairing/claim"

    def test_offer_and_store_share_exact_expiry_boundary(
        self, pairing_client, main_installation
    ):
        body = _mint(pairing_client)
        offer = _offer_of(body["payload"])
        assert alice_pairing._offers[offer["t"]]["expires_at"] == offer["e"]
        assert 299 <= offer["e"] - time.time() <= 300

    def test_qr_contains_no_long_lived_credentials(self, pairing_client, main_installation):
        payload = _mint(pairing_client)["payload"]
        assert MAIN_KEY not in payload
        assert MAIN_KEY not in json.dumps(_offer_of(payload))


# ---------------------------------------------------------------------------
# Session endpoint — auth, addresses, replacement
# ---------------------------------------------------------------------------


class TestSessionEndpoint:
    def test_requires_session_token(self, pairing_client, main_installation):
        assert pairing_client.post(SESSION_URL).status_code == 401

    def test_undiscoverable_address_is_503(
        self, pairing_client, main_installation, monkeypatch
    ):
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: None)
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503
        assert "address" in resp.text.lower()

    def test_invalid_configured_address_is_503(
        self, pairing_client, main_installation, monkeypatch
    ):
        monkeypatch.setattr(
            alice_pairing,
            "_pairing_setting",
            lambda request, key, default: "http://evil.example/x" if key == "address" else default,
        )
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503

    def test_loopback_dashboard_without_serve_forward_is_published_automatically(
        self, pairing_client, main_installation, automation
    ):
        web_server.app.state.bound_host = "127.0.0.1"
        headers = {**_session_headers(), "Host": "127.0.0.1:9119"}
        resp = pairing_client.post(SESSION_URL, headers=headers)
        assert resp.status_code == 200
        assert [
            "tailscale", "serve", "--bg", "--yes", "--tcp", "9119",
            "tcp://127.0.0.1:9119",
        ] in automation["serve"]

    def test_loopback_dashboard_behind_serve_forward_is_reachable(
        self, pairing_client, main_installation, monkeypatch
    ):
        """The documented setup: dashboard on loopback, Tailscale Serve
        publishing the same port to the tailnet. The phone can reach the
        claim through Serve, so minting must succeed."""
        web_server.app.state.bound_host = "127.0.0.1"
        monkeypatch.setattr(
            alice_pairing,
            "_tailscale_tcp_forward_target",
            lambda port: f"tcp://127.0.0.1:{port}",
        )
        headers = {**_session_headers(), "Host": "127.0.0.1:9119"}
        resp = pairing_client.post(SESSION_URL, headers=headers)
        assert resp.status_code == 200

    def test_gateway_is_probed_on_localhost_when_serve_publishes_it(
        self, pairing_client, main_installation, automation, monkeypatch
    ):
        seen = {}

        def probe(address, port, key):
            seen.update(address=address, port=port, key=key)

        monkeypatch.setattr(alice_pairing, "_probe_gateway", probe)
        monkeypatch.setattr(
            alice_pairing,
            "_tailscale_tcp_forward_target",
            lambda port: f"tcp://127.0.0.1:{port}",
        )
        body = _mint(pairing_client)
        assert seen == {"address": "127.0.0.1", "port": 8643, "key": MAIN_KEY}
        # Regression: the QR still advertises the tailnet address while the
        # probe used the localhost target of the Serve forward.
        assert _offer_of(body["payload"])["c"].startswith("http://100.67.213.42:9119/")

    def test_new_code_invalidates_previous_code(self, pairing_client, main_installation):
        first = _offer_of(_mint(pairing_client)["payload"])["t"]
        second = _offer_of(_mint(pairing_client)["payload"])["t"]
        assert first != second
        old = pairing_client.post(CLAIM_URL, json={"token": first})
        assert old.status_code == 404
        assert old.json() == {"error": "unknown"}
        assert pairing_client.post(CLAIM_URL, json={"token": second}).status_code == 200


# ---------------------------------------------------------------------------
# Main-gateway provisioning — idempotent, preserving operator values
# ---------------------------------------------------------------------------


class TestGatewayProvisioning:
    def test_pairing_does_not_change_the_sticky_active_profile(
        self, pairing_client, automation, monkeypatch
    ):
        """Pairing identity is resolved independently; it must not rewrite the
        operator's currently active/selected profile as a side effect."""
        home = Path(os.environ["HERMES_HOME"])
        monkeypatch.setattr(
            alice_pairing, "list_profiles", lambda: _fake_profiles(home, main_running=False)
        )
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
        monkeypatch.setattr(alice_pairing, "_tailscale_dns_name", lambda: None)
        monkeypatch.setattr(alice_pairing, "_probe_gateway", lambda address, port, key: None)
        monkeypatch.setattr(
            "hermes_cli.profiles.set_active_profile",
            lambda _name: pytest.fail("pairing must not change the active profile"),
        )

        assert _mint(pairing_client)["profile"] == "default"

    def test_unprovisioned_installation_gets_a_working_gateway(
        self, pairing_client, automation, monkeypatch
    ):
        """No root .env, no running gateway: pairing creates the settings,
        installs and starts the service, and still delivers the main profile."""
        home = Path(os.environ["HERMES_HOME"])
        monkeypatch.setattr(
            alice_pairing, "list_profiles", lambda: _fake_profiles(home, main_running=False)
        )
        monkeypatch.setattr("hermes_cli.profiles.get_active_profile", lambda: "radar-ia")
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
        monkeypatch.setattr(alice_pairing, "_tailscale_dns_name", lambda: None)
        monkeypatch.setattr(alice_pairing, "_probe_gateway", lambda address, port, key: None)

        body = _mint(pairing_client)
        assert body["profile"] == "default"
        assert automation["start"] == 1

        env = (home / ".env").read_text(encoding="utf-8")
        assert "API_SERVER_KEY=" in env
        assert "API_SERVER_HOST=127.0.0.1" in env
        port_line = next(
            line for line in env.splitlines() if line.startswith("API_SERVER_PORT=")
        )
        assert int(port_line.split("=")[1]) in alice_pairing.MAIN_GATEWAY_PORT_CANDIDATES

        offer = _offer_of(body["payload"])
        assert offer["c"].startswith("http://100.67.213.42:9119/")
        assert "API_SERVER_KEY=" not in json.dumps(offer)

    def test_existing_gateway_values_are_never_overwritten(
        self, pairing_client, main_installation, automation
    ):
        """An operator-set key/port/host survive pairing untouched; the Serve
        forward for the configured port is still ensured."""
        before = (main_installation / ".env").read_text(encoding="utf-8")
        _mint(pairing_client)
        assert (main_installation / ".env").read_text(encoding="utf-8") == before
        assert automation["serve"] == [
            ["tailscale", "serve", "--bg", "--yes", "--tcp", "8643", "tcp://127.0.0.1:8643"]
        ]

    def test_running_gateway_is_never_restarted(self, pairing_client, main_installation, automation):
        _mint(pairing_client)
        assert automation["start"] == 0

    def test_provisioning_is_pinned_to_the_main_profile_home(
        self, main_installation, monkeypatch
    ):
        """Regression: the dashboard's ambient profile scope can be a BOT
        (the sticky active profile). Env provisioning must land in the main
        profile's .env (the installation root), never in the bot's."""
        from hermes_constants import (
            reset_hermes_home_override,
            set_hermes_home_override,
        )

        home = Path(os.environ["HERMES_HOME"])
        bot_home = home / "profiles" / "radar-ia"
        bot_env_before = (bot_home / ".env").read_text(encoding="utf-8")
        token = set_hermes_home_override(bot_home)
        try:
            with alice_pairing._main_profile_scope("default"):
                alice_pairing._provision_main_gateway_env({})
        finally:
            reset_hermes_home_override(token)

        assert "API_SERVER_KEY=" in (home / ".env").read_text(encoding="utf-8")
        assert (bot_home / ".env").read_text(encoding="utf-8") == bot_env_before

    def test_pairing_does_not_rewrite_platform_configuration(
        self, pairing_client, automation, monkeypatch
    ):
        """Provisioning connectivity must not silently disable messaging or
        otherwise change the operator's platform intent."""
        import yaml

        home = Path(os.environ["HERMES_HOME"])
        (home / "profiles" / "radar-ia").mkdir(parents=True, exist_ok=True)
        (home / ".env").write_text(
            "API_SERVER_HOST=127.0.0.1\n"
            "API_SERVER_PORT=8643\n"
            f"API_SERVER_KEY={MAIN_KEY}\n"
            "TELEGRAM_BOT_TOKEN=tok-abc\n"
            "WHATSAPP_ENABLED=true\n",
            encoding="utf-8",
        )
        (home / "config.yaml").write_text(
            "platforms:\n  telegram:\n    enabled: true\n",
            encoding="utf-8",
        )
        before = (yaml.safe_load((home / "config.yaml").read_text()) or {}).get("platforms")
        monkeypatch.setattr(
            alice_pairing, "list_profiles", lambda: _fake_profiles(home, main_running=False)
        )
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
        monkeypatch.setattr(alice_pairing, "_tailscale_dns_name", lambda: None)
        monkeypatch.setattr(alice_pairing, "_probe_gateway", lambda address, port, key: None)

        assert _mint(pairing_client)["profile"] == "default"
        after = (yaml.safe_load((home / "config.yaml").read_text()) or {}).get("platforms")
        assert after == before

    def test_pairing_never_stops_a_running_named_profile_gateway(
        self, pairing_client, automation, monkeypatch
    ):
        home = Path(os.environ["HERMES_HOME"])
        monkeypatch.setattr(
            alice_pairing, "list_profiles", lambda: _fake_profiles(home, main_running=False)
        )
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
        monkeypatch.setattr(alice_pairing, "_tailscale_dns_name", lambda: None)
        monkeypatch.setattr(alice_pairing, "_probe_gateway", lambda address, port, key: None)
        monkeypatch.setattr(
            "hermes_cli.gateway.stop_profile_gateway",
            lambda: pytest.fail("pairing must not stop sibling profile gateways"),
        )

        assert _mint(pairing_client)["profile"] == "default"
        assert automation["start"] == 1

    def test_gateway_start_failure_is_503_and_mints_nothing(
        self, pairing_client, automation, monkeypatch
    ):
        home = Path(os.environ["HERMES_HOME"])
        monkeypatch.setattr(
            alice_pairing, "list_profiles", lambda: _fake_profiles(home, main_running=False)
        )
        monkeypatch.setattr("hermes_cli.profiles.get_active_profile", lambda: "radar-ia")
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
        monkeypatch.setattr(alice_pairing, "_probe_gateway", lambda address, port, key: None)

        def boom():
            raise RuntimeError("launchd refused")

        monkeypatch.setattr(alice_pairing, "launchd_start", boom)
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503
        assert alice_pairing._offers == {}

    def test_port_allocation_skips_taken_ports(self, monkeypatch):
        class TakenSocket:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def bind(self, address):
                if address[1] == 8643:
                    raise OSError("address already in use")

        monkeypatch.setattr(alice_pairing.socket, "socket", TakenSocket)
        assert alice_pairing._allocate_gateway_port() == 8644

    def test_stale_routable_host_and_taken_port_are_reconciled(self, monkeypatch):
        """Root .env values left over from an older setup (a hardcoded
        tailnet IP plus a port another gateway already holds) must not produce
        a dead main gateway: they are reconciled to a free localhost port
        while the existing key is preserved."""
        env = {
            "API_SERVER_HOST": "100.67.213.42",
            "API_SERVER_PORT": "8642",
            "API_SERVER_KEY": MAIN_KEY,
        }
        monkeypatch.setattr(alice_pairing, "_port_bindable", lambda address, port: False)
        monkeypatch.setattr(
            alice_pairing, "_allocate_gateway_port", lambda: 8643
        )
        written = alice_pairing._provision_main_gateway_env(env)
        assert written == {"API_SERVER_HOST": "127.0.0.1", "API_SERVER_PORT": "8643"}
        # The key is never part of a reconciliation write.
        assert "API_SERVER_KEY" not in written

    def test_workable_existing_port_and_local_host_are_respected(self, monkeypatch):
        env = {
            "API_SERVER_HOST": "127.0.0.1",
            "API_SERVER_PORT": "8643",
            "API_SERVER_KEY": MAIN_KEY,
        }
        monkeypatch.setattr(alice_pairing, "_port_bindable", lambda address, port: True)
        assert alice_pairing._provision_main_gateway_env(env) == {}

    def test_live_main_gateway_settings_are_never_reconciled_under_it(self, monkeypatch):
        env = {
            "API_SERVER_HOST": "127.0.0.1",
            "API_SERVER_PORT": "8643",
            "API_SERVER_KEY": MAIN_KEY,
        }
        monkeypatch.setattr(alice_pairing, "_port_bindable", lambda address, port: False)
        assert alice_pairing._provision_main_gateway_env(env, gateway_running=True) == {}

    def test_missing_key_after_provisioning_is_503_not_a_leak(
        self, pairing_client, automation, monkeypatch
    ):
        """If provisioning cannot deliver a key (e.g. a blocked .env write),
        the endpoint fails closed with an explicit error and no offer exists."""
        home = Path(os.environ["HERMES_HOME"])
        monkeypatch.setattr(
            alice_pairing, "list_profiles", lambda: _fake_profiles(home, main_running=False)
        )
        monkeypatch.setattr("hermes_cli.profiles.get_active_profile", lambda: "radar-ia")
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
        monkeypatch.setattr(alice_pairing, "_probe_gateway", lambda address, port, key: None)
        monkeypatch.setattr(alice_pairing, "_provision_main_gateway_env", lambda env, **_kwargs: {})
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503
        assert "API_SERVER_KEY" in resp.json()["detail"]
        assert alice_pairing._offers == {}


# ---------------------------------------------------------------------------
# Tailscale Serve publication
# ---------------------------------------------------------------------------


class TestTailscaleServeForward:
    def test_missing_forward_is_added_with_the_documented_argv(
        self, pairing_client, main_installation, automation
    ):
        _mint(pairing_client)
        assert automation["serve"] == [
            ["tailscale", "serve", "--bg", "--yes", "--tcp", "8643", "tcp://127.0.0.1:8643"]
        ]

    def test_matching_forward_is_left_alone(
        self, pairing_client, main_installation, automation, monkeypatch
    ):
        monkeypatch.setattr(
            alice_pairing,
            "_tailscale_tcp_forward_target",
            lambda port: f"tcp://127.0.0.1:{port}",
        )
        _mint(pairing_client)
        assert automation["serve"] == []

    def test_stale_forward_on_the_gateway_port_converges(
        self, pairing_client, main_installation, automation, monkeypatch
    ):
        monkeypatch.setattr(
            alice_pairing, "_tailscale_tcp_forward_target", lambda port: "tcp://127.0.0.1:9999"
        )
        _mint(pairing_client)
        assert automation["serve"] != []

    def test_serve_failure_is_503(self, pairing_client, main_installation, automation, monkeypatch):
        def failing_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, "", "tailscale: permission denied")

        monkeypatch.setattr(alice_pairing.subprocess, "run", failing_run)
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503
        assert "Tailscale" in resp.json()["detail"]

    def test_forward_target_parses_the_real_status_shape(self, monkeypatch):
        payload = json.dumps(
            {
                "TCP": {
                    "443": {"HTTPS": True},
                    "8642": {"TCPForward": "127.0.0.1:8642"},
                }
            }
        )

        def fake_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, payload, "")

        monkeypatch.setattr(alice_pairing.subprocess, "run", fake_run)
        assert alice_pairing._tailscale_tcp_forward_target(8642) == "127.0.0.1:8642"
        assert alice_pairing._tailscale_tcp_forward_target(9999) is None


# ---------------------------------------------------------------------------
# Claim endpoint — one-time exchange
# ---------------------------------------------------------------------------


class TestClaimEndpoint:
    def test_tailnet_phone_claims_once_and_credentials_are_not_retained(
        self, pairing_client, main_installation, monkeypatch
    ):
        monkeypatch.setattr(
            "hermes_cli.config.get_env_value_prefer_dotenv",
            lambda key: {
                "HERMES_DASHBOARD_BASIC_AUTH_USERNAME": "marc",
                "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD": "pw",
            }.get(key),
        )
        token = _offer_of(_mint(pairing_client)["payload"])["t"]

        first = pairing_client.post(
            CLAIM_URL, json={"token": token, "device_name": "iPhone"}
        )
        assert first.status_code == 200
        assert first.json() == {
            "profile": "default",
            "profile_display_name": "Alice",
            "gateway": {
                "url": "http://100.67.213.42:8643",
                "key": MAIN_KEY,
            },
            "dashboard": {
                "url": "http://100.67.213.42:9119",
                "username": "marc",
                "password": "pw",
            },
        }
        assert "config" not in alice_pairing._offers[token]

        second = pairing_client.post(CLAIM_URL, json={"token": token})
        assert second.status_code == 410
        assert second.json() == {"error": "used"}

    def test_claim_without_dashboard_credentials_is_valid(
        self, pairing_client, main_installation
    ):
        token = _offer_of(_mint(pairing_client)["payload"])["t"]
        resp = pairing_client.post(CLAIM_URL, json={"token": token})
        assert resp.status_code == 200
        assert resp.json()["dashboard"] is None

    def test_expired_offer_is_gone(self, pairing_client, main_installation, monkeypatch):
        token = _offer_of(_mint(pairing_client)["payload"])["t"]
        expires = alice_pairing._offers[token]["expires_at"]
        monkeypatch.setattr(alice_pairing.time, "time", lambda: expires)
        resp = pairing_client.post(CLAIM_URL, json={"token": token})
        assert resp.status_code == 410
        assert resp.json() == {"error": "expired"}

    def test_unknown_token_is_404(self, pairing_client):
        resp = pairing_client.post(CLAIM_URL, json={"token": "no-such-token"})
        assert resp.status_code == 404
        assert resp.json() == {"error": "unknown"}

    def test_spoofed_forwarded_for_cannot_cross_source_gate(self, pairing_client):
        resp = _client_from(LAN_IP).post(
            CLAIM_URL,
            json={"token": "whatever"},
            headers={"X-Forwarded-For": PHONE_IP},
        )
        assert resp.status_code == 403

    def test_reverse_proxy_headers_fail_closed_even_from_loopback(self, pairing_client):
        resp = _client_from("127.0.0.1").post(
            CLAIM_URL,
            json={"token": "whatever"},
            headers={"X-Forwarded-For": PHONE_IP},
        )
        assert resp.status_code == 403

    def test_ipv4_mapped_tailnet_peer_is_accepted_by_network_rule(self):
        assert alice_pairing._origin_allowed("::ffff:100.70.100.2")

    def test_lan_and_public_sources_are_always_forbidden(self, pairing_client):
        for ip in (LAN_IP, "8.8.8.8", "100.64.999.1"):
            resp = _client_from(ip).post(CLAIM_URL, json={"token": "whatever"})
            assert resp.status_code == 403
            assert resp.json() == {"error": "forbidden"}

    def test_oversized_body_is_rejected_without_echo(self, pairing_client):
        resp = pairing_client.post(
            CLAIM_URL, content=b"x" * (alice_pairing.CLAIM_BODY_MAX_BYTES + 1)
        )
        assert resp.status_code == 404
        assert "x" * 100 not in resp.text

    def test_extra_body_fields_are_rejected(self, pairing_client):
        resp = pairing_client.post(
            CLAIM_URL, json={"token": "nope", "unexpected": "field"}
        )
        assert resp.status_code == 404

    def test_device_name_is_sanitized(self, pairing_client, main_installation, monkeypatch):
        seen = {}
        real_audit = alice_pairing.audit_log

        def spy(event, **fields):
            if event is alice_pairing.AuditEvent.PAIRING_CLAIMED:
                seen.update(fields)
            real_audit(event, **fields)

        monkeypatch.setattr(alice_pairing, "audit_log", spy)
        token = _offer_of(_mint(pairing_client)["payload"])["t"]
        pairing_client.post(
            CLAIM_URL, json={"token": token, "device_name": " iPhone\x00 de \nprueba "}
        )
        assert seen["device"] == "iPhone de prueba"

    def test_claim_attempts_are_rate_limited_per_ip(self, pairing_client):
        for _ in range(alice_pairing.CLAIM_RATE_MAX_PER_WINDOW):
            resp = pairing_client.post(CLAIM_URL, json={"token": "nope"})
            assert resp.status_code == 404
        assert pairing_client.post(CLAIM_URL, json={"token": "nope"}).status_code == 429


class TestAdvertisedAddressPreference:
    def test_magicdns_name_is_preferred_over_the_ip(
        self, pairing_client, main_installation, monkeypatch
    ):
        monkeypatch.setattr(
            alice_pairing, "_tailscale_dns_name", lambda: "machine.tailnet.ts.net"
        )
        offer = _offer_of(_mint(pairing_client)["payload"])
        assert offer["c"].startswith("http://machine.tailnet.ts.net:9119/")

    def test_raw_ip_is_used_when_there_is_no_dns_name(
        self, pairing_client, main_installation
    ):
        offer = _offer_of(_mint(pairing_client)["payload"])
        assert offer["c"].startswith("http://100.67.213.42:9119/")
