"""Tests for the Alice QR-pairing dashboard routes.

These tests pin Alice v1's exact two-field deep-link envelope, profile
selection, one-time/expiry semantics, tailnet-only claim boundary and the
fact that long-lived credentials disappear from the offer store after claim.
"""
from __future__ import annotations

import base64
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
PHONE_IP = "100.70.100.2"
LAN_IP = "192.168.1.5"


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


@pytest.fixture
def gateway_profile(monkeypatch):
    profile_home = Path(os.environ["HERMES_HOME"]) / "profiles" / "radar-ia"
    profile_home.mkdir(parents=True, exist_ok=True)
    (profile_home / ".env").write_text(
        "API_SERVER_ENABLED=true\n"
        "API_SERVER_PORT=8642\n"
        "API_SERVER_KEY=test-gateway-key-0123456789abcdef\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("hermes_cli.profiles.get_active_profile", lambda: "radar-ia")
    monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
    monkeypatch.setattr(alice_pairing, "_probe_gateway", lambda address, port, key: None)
    return profile_home


def _session_headers():
    return {"X-Hermes-Session-Token": web_server._SESSION_TOKEN}


def _mint(client: TestClient, profile: str | None = None) -> dict:
    url = SESSION_URL
    if profile is not None:
        url += f"?profile={urllib.parse.quote(profile)}"
    resp = client.post(url, headers=_session_headers())
    assert resp.status_code == 200, resp.text
    return resp.json()


def _offer_of(payload: str) -> dict:
    query = urllib.parse.parse_qs(urllib.parse.urlparse(payload).query)
    padded = query["p"][0] + "=" * (-len(query["p"][0]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class TestProtocolShape:
    def test_link_is_exact_alice_v1_shape(self, pairing_client, gateway_profile):
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
        assert offer["pr"] == "radar-ia"
        assert offer["c"] == "http://100.67.213.42:9119/api/alice/pairing/claim"

    def test_offer_and_store_share_exact_expiry_boundary(
        self, pairing_client, gateway_profile
    ):
        body = _mint(pairing_client)
        offer = _offer_of(body["payload"])
        assert alice_pairing._offers[offer["t"]]["expires_at"] == offer["e"]
        assert 299 <= offer["e"] - time.time() <= 300

    def test_qr_contains_no_long_lived_credentials(self, pairing_client, gateway_profile):
        payload = _mint(pairing_client)["payload"]
        assert "test-gateway-key" not in payload
        assert "test-gateway-key" not in json.dumps(_offer_of(payload))


class TestSessionEndpoint:
    def test_requires_session_token(self, pairing_client, gateway_profile):
        assert pairing_client.post(SESSION_URL).status_code == 401

    def test_explicit_management_profile_wins(
        self, pairing_client, gateway_profile, monkeypatch
    ):
        monkeypatch.setattr("hermes_cli.profiles.get_active_profile", lambda: "default")
        body = _mint(pairing_client, "radar-ia")
        assert body["profile"] == "radar-ia"
        assert _offer_of(body["payload"])["pr"] == "radar-ia"

    def test_invalid_profile_is_rejected(self, pairing_client, gateway_profile):
        resp = pairing_client.post(
            f"{SESSION_URL}?profile=../escape", headers=_session_headers()
        )
        assert resp.status_code == 400

    def test_unknown_profile_is_rejected(self, pairing_client, gateway_profile):
        resp = pairing_client.post(
            f"{SESSION_URL}?profile=does-not-exist", headers=_session_headers()
        )
        assert resp.status_code == 404

    def test_undiscoverable_address_is_503(
        self, pairing_client, gateway_profile, monkeypatch
    ):
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: None)
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503
        assert "address" in resp.text.lower()

    def test_invalid_configured_address_is_503(
        self, pairing_client, gateway_profile, monkeypatch
    ):
        monkeypatch.setattr(
            alice_pairing,
            "_pairing_setting",
            lambda request, key, default: "http://evil.example/x" if key == "address" else default,
        )
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503

    def test_loopback_only_dashboard_refuses_to_mint(
        self, pairing_client, gateway_profile
    ):
        web_server.app.state.bound_host = "127.0.0.1"
        headers = {**_session_headers(), "Host": "127.0.0.1:9119"}
        resp = pairing_client.post(SESSION_URL, headers=headers)
        assert resp.status_code == 503
        assert "local-only" in resp.text

    def test_gateway_is_probed_on_the_advertised_host(
        self, pairing_client, gateway_profile, monkeypatch
    ):
        seen = {}

        def probe(address, port, key):
            seen.update(address=address, port=port, key=key)

        monkeypatch.setattr(alice_pairing, "_probe_gateway", probe)
        _mint(pairing_client)
        assert seen == {
            "address": "100.67.213.42",
            "port": 8642,
            "key": "test-gateway-key-0123456789abcdef",
        }

    def test_missing_gateway_key_is_503_not_a_leak(self, pairing_client, monkeypatch):
        monkeypatch.setattr("hermes_cli.profiles.get_active_profile", lambda: "radar-ia")
        monkeypatch.setattr(alice_pairing, "_tailscale_ipv4", lambda: "100.67.213.42")
        resp = pairing_client.post(SESSION_URL, headers=_session_headers())
        assert resp.status_code == 503
        assert "test-gateway-key" not in resp.text

    def test_new_code_invalidates_previous_code(self, pairing_client, gateway_profile):
        first = _offer_of(_mint(pairing_client)["payload"])["t"]
        second = _offer_of(_mint(pairing_client)["payload"])["t"]
        assert first != second
        old = pairing_client.post(CLAIM_URL, json={"token": first})
        assert old.status_code == 404
        assert old.json() == {"error": "unknown"}
        assert pairing_client.post(CLAIM_URL, json={"token": second}).status_code == 200


class TestClaimEndpoint:
    def test_tailnet_phone_claims_once_and_credentials_are_not_retained(
        self, pairing_client, gateway_profile, monkeypatch
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
            "profile": "radar-ia",
            "gateway": {
                "url": "http://100.67.213.42:8642",
                "key": "test-gateway-key-0123456789abcdef",
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
        self, pairing_client, gateway_profile
    ):
        token = _offer_of(_mint(pairing_client)["payload"])["t"]
        resp = pairing_client.post(CLAIM_URL, json={"token": token})
        assert resp.status_code == 200
        assert resp.json()["dashboard"] is None

    def test_expired_offer_is_gone(self, pairing_client, gateway_profile, monkeypatch):
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
            resp = pairing_client.post(CLAIM_URL, json={"token": "nope"})
            assert resp.status_code == 404
        assert pairing_client.post(CLAIM_URL, json={"token": "nope"}).status_code == 429
