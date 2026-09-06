"""Tests for the Alice QR-pairing dashboard routes.

The dashboard is the Mac side of the handshake the Alice iOS app already
speaks (protocol doc lives in the Alice repo: ``docs/pairing.md``). These
tests pin the wire format the phone depends on — deep-link shape, one-time
claim, tailnet-only source gate, rate limits — and that no response path
leaks more than the claim contract allows.

Session-endpoint auth runs through the REAL ``_require_token`` in loopback
mode (``X-Hermes-Session-Token``); the claim runs through the real
``PUBLIC_API_PATHS`` allowlist with no credentials at all, from a peer
address the test pins (the gate reads the peer, never a spoofable header).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hermes_cli import web_server
from hermes_cli.web_routers import alice_pairing


SESSION_URL = "/api/alice/pairing/session"
CLAIM_URL = "/api/alice/pairing/claim"
PHONE_IP = "100.70.100.2"  # tailnet peer, inside 100.64.0.0/10
LAN_IP = "192.168.1.5"  # hostile-LAN threat model


@pytest.fixture
def pairing_client():
    """Loopback-mode app + hermetic pairing state, restored on exit."""
    alice_pairing._reset_claim_state_for_tests()
    prev_required = getattr(web_server.app.state, "auth_required", None)
    prev_port = getattr(web_server.app.state, "bound_port", None)
    web_server.app.state.auth_required = False
    web_server.app.state.bound_port = 9119
    yield TestClient(
        web_server.app, base_url="http://testserver", client=(PHONE_IP, 50000)
    )
    web_server.app.state.auth_required = prev_required
    web_server.app.state.bound_port = prev_port
    alice_pairing._reset_claim_state_for_tests()


def _client_from(ip: str) -> TestClient:
    """A caller arriving from ``ip`` — the peer address, not a spoofable header."""
    return TestClient(web_server.app, base_url="http://testserver", client=(ip, 50000))


@pytest.fixture
def gateway_profile(monkeypatch):
    """A profile whose .env carries a gateway key, the way launchd profiles do."""
    profile_home = Path(os.environ["HERMES_HOME"]) / "profiles" / "radar-ia"
    profile_home.mkdir(parents=True)
    (profile_home / ".env").write_text(
        "API_SERVER_ENABLED=true\n"
        "API_SERVER_PORT=8642\n"
        "API_SERVER_KEY=test-gateway-key-0123456789abcdef\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("hermes_cli.profiles.get_active_profile", lambda: "radar-ia")
    monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
    return profile_home


def _session_headers():
    return {"X-Hermes-Session-Token": web_server._SESSION_TOKEN}


def _mint(client: TestClient) -> dict:
    resp = client.post(SESSION_URL, headers=_session_headers())
    assert resp.status_code == 200
    return resp.json()


def _offer_of(payload: str) -> dict:
    """Decode the deep link the same way the iOS client does."""
    query = urllib.parse.parse_qs(urllib.parse.urlparse(payload).query)
    padded = query["p"][0] + "=" * (-len(query["p"][0]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# ---------------------------------------------------------------------------
# Protocol shape — what the phone parses
# ---------------------------------------------------------------------------


class TestProtocolShape:
    def test_link_is_the_documented_alice_pair_shape(self, pairing_client, gateway_profile):
        payload = _mint(pairing_client)["payload"]
        assert payload.startswith("alice://pair?v=1&p=")
        assert "&s=" in payload

        offer = _offer_of(payload)
        assert set(offer) == {"c", "t", "e", "pr"}
        assert offer["pr"] == "radar-ia"
        assert offer["c"].endswith("/api/alice/pairing/claim")
        assert offer["c"].startswith("http://100.67.213.42:9119/")

    def test_signature_covers_the_payload_bytes(self, pairing_client, gateway_profile):
        payload = _mint(pairing_client)["payload"]
        query = urllib.parse.parse_qs(urllib.parse.urlparse(payload).query)
        padded = query["p"][0] + "=" * (-len(query["p"][0]) % 4)
        raw = base64.urlsafe_b64decode(padded)
        expected = hmac.new(alice_pairing._secret, raw, hashlib.sha256).hexdigest()
        assert query["s"][0] == expected

    def test_minted_link_passes_self_verification(self, pairing_client, gateway_profile):
        assert alice_pairing._self_verify(_mint(pairing_client)["payload"])

    def test_offer_ttl_is_five_minutes(self, pairing_client, gateway_profile):
        body = _mint(pairing_client)
        offer = _offer_of(body["payload"])
        now = time.time()
        assert 290 <= offer["e"] - now <= 300
        assert body["profile"] == "radar-ia"

    def test_no_secrets_inside_the_deep_link(self, pairing_client, gateway_profile):
        offer = _offer_of(_mint(pairing_client)["payload"])
        assert "test-gateway-key" not in json.dumps(offer)


# ---------------------------------------------------------------------------
# POST /api/alice/pairing/session — authenticated minting
# ---------------------------------------------------------------------------


class TestSessionEndpoint:
    def test_requires_session_token(self, pairing_client, gateway_profile):
        resp = pairing_client.post(SESSION_URL)
        assert resp.status_code == 401

    def test_returns_configuration_shape(self, pairing_client, gateway_profile):
        body = _mint(pairing_client)
        assert body["profile"] == "radar-ia"
        assert body["expires_at"]

    def test_undiscoverable_address_is_a_503_with_guidance(
        self, pairing_client, gateway_profile, monkeypatch
    ):
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: None)
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503
        assert "dashboard.alice_pairing.address" in resp.json()["detail"]

    def test_missing_gateway_key_is_a_503_not_a_leak(self, pairing_client, monkeypatch):
        monkeypatch.setattr("hermes_cli.profiles.get_active_profile", lambda: "radar-ia")
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503
        assert "test-gateway-key" not in resp.text


# ---------------------------------------------------------------------------
# POST /api/alice/pairing/claim — the one-time exchange
# ---------------------------------------------------------------------------


class TestClaimEndpoint:
    def test_phone_inside_the_tailnet_claims_once(
        self, pairing_client, gateway_profile, monkeypatch
    ):
        monkeypatch.setattr(
            "hermes_cli.config.get_env_value_prefer_dotenv",
            lambda key: {"HERMES_DASHBOARD_BASIC_AUTH_USERNAME": "marc",
                         "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD": "pw"}.get(key),
        )
        token = _offer_of(_mint(pairing_client)["payload"])["t"]

        first = pairing_client.post(CLAIM_URL, json={"token": token, "device_name": "iPhone"})
        assert first.status_code == 200
        body = first.json()
        assert body["profile"] == "radar-ia"
        assert body["gateway"] == {
            "url": "http://100.67.213.42:8642",
            "key": "test-gateway-key-0123456789abcdef",
        }
        assert body["dashboard"] == {
            "url": "http://100.67.213.42:9119",
            "username": "marc",
            "password": "pw",
        }

        second = pairing_client.post(CLAIM_URL, json={"token": token, "device_name": "iPhone"})
        assert second.status_code == 410
        assert second.json() == {"error": "used"}

    def test_claim_without_dashboard_credentials_omits_the_section(
        self, pairing_client, gateway_profile
    ):
        token = _offer_of(_mint(pairing_client)["payload"])["t"]
        resp = pairing_client.post(CLAIM_URL, json={"token": token})
        assert resp.status_code == 200
        assert resp.json()["dashboard"] is None

    def test_expired_offer_reads_as_gone(self, pairing_client, gateway_profile, monkeypatch):
        token = _offer_of(_mint(pairing_client)["payload"])["t"]
        real_time = time.time
        monkeypatch.setattr(alice_pairing.time, "time", lambda: real_time() + 301)
        resp = pairing_client.post(CLAIM_URL, json={"token": token})
        assert resp.status_code == 410
        assert resp.json() == {"error": "expired"}

    def test_unknown_token_is_404(self, pairing_client):
        resp = pairing_client.post(CLAIM_URL, json={"token": "no-such-token"})
        assert resp.status_code == 404
        assert resp.json() == {"error": "unknown"}

    def test_spoofed_forwarded_for_cannot_cross_the_source_gate(self, pairing_client):
        # A hostile-LAN caller forging a tailnet X-Forwarded-For must stay out:
        # the gate reads the peer address only.
        resp = _client_from(LAN_IP).post(
            CLAIM_URL,
            json={"token": "whatever", "device_name": "iPhone"},
            headers={"X-Forwarded-For": PHONE_IP},
        )
        assert resp.status_code == 403

    def test_foreign_source_addresses_are_forbidden(self, pairing_client):
        for ip in (LAN_IP, "8.8.8.8"):
            resp = _client_from(ip).post(CLAIM_URL, json={"token": "whatever"})
            assert resp.status_code == 403
            assert resp.json() == {"error": "forbidden"}

    def test_allow_lan_relaxes_the_source_gate(
        self, pairing_client, gateway_profile, monkeypatch
    ):
        monkeypatch.setattr(
            alice_pairing,
            "_pairing_setting",
            lambda request, key, default: True if key == "allow_lan" else default,
        )
        token = _offer_of(_mint(pairing_client)["payload"])["t"]
        resp = _client_from(LAN_IP).post(CLAIM_URL, json={"token": token})
        assert resp.status_code == 200

    def test_oversized_body_is_unknown_not_an_echo(self, pairing_client):
        resp = pairing_client.post(
            CLAIM_URL, content=b"x" * (alice_pairing.CLAIM_BODY_MAX_BYTES + 1)
        )
        assert resp.status_code == 404

    def test_device_name_is_sanitized(self, pairing_client, gateway_profile, monkeypatch):
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
            resp = pairing_client.post(
                CLAIM_URL, json={"token": "nope", "device_name": "iPhone"}
            )
            assert resp.status_code == 404
        resp = pairing_client.post(CLAIM_URL, json={"token": "nope", "device_name": "iPhone"})
        assert resp.status_code == 429
