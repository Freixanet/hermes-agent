"""Bot Chat cron delivery: deliver='bot-chat[:<profile>]' injects job output
into a local profile's canonical Bot Chat session as a real inbound turn.

Covers token parsing, target resolution (own profile / named / missing),
preflight exemption, create-time validation, the subprocess delivery lane,
and the delivery-targets listing used by UI pickers.
"""

from unittest import mock

import pytest

from cron import scheduler as sched
from cron import scheduler_delivery as sched_delivery
from cron.scheduler import _resolve_delivery_targets
from cron.scheduler_delivery import (
    BOT_CHAT_PLATFORM,
    _deliver_to_bot_chat,
    _resolve_bot_chat_target,
    parse_bot_chat_deliver_token,
)
from cron.scheduler_preflight import _preflight_check_delivery


# ── token parsing ────────────────────────────────────────────────────────────

def test_bare_token_targets_own_profile():
    assert parse_bot_chat_deliver_token("bot-chat") == ""
    assert parse_bot_chat_deliver_token("  Bot-Chat  ") == ""


def test_named_token_returns_profile():
    assert parse_bot_chat_deliver_token("bot-chat:research") == "research"
    assert parse_bot_chat_deliver_token("BOT-CHAT:Research") == "Research"


def test_non_bot_chat_tokens_pass_through():
    assert parse_bot_chat_deliver_token("telegram:-100:17") is None
    assert parse_bot_chat_deliver_token("origin") is None
    assert parse_bot_chat_deliver_token("local") is None
    assert parse_bot_chat_deliver_token("all") is None
    # A platform whose name merely CONTAINS bot-chat must not match.
    assert parse_bot_chat_deliver_token("bot-chatter") is None


# ── target resolution ────────────────────────────────────────────────────────

def test_own_profile_resolves_without_name():
    target = _resolve_bot_chat_target({"id": "j1"}, "")
    assert target == {"platform": BOT_CHAT_PLATFORM, "chat_id": "", "thread_id": None}


def test_named_profile_resolves_when_exists():
    with mock.patch("hermes_cli.profiles.profile_exists", return_value=True):
        target = _resolve_bot_chat_target({"id": "j1"}, "research")
    assert target is not None
    assert target["platform"] == BOT_CHAT_PLATFORM
    assert target["chat_id"] == "research"


def test_unknown_profile_resolves_to_none():
    with mock.patch("hermes_cli.profiles.profile_exists", return_value=False):
        assert _resolve_bot_chat_target({"id": "j1"}, "ghost") is None


def test_resolve_delivery_targets_combines_with_platform_targets():
    """bot-chat rides the same comma-separated deliver string as platforms."""
    job = {"id": "j1", "deliver": "bot-chat,telegram"}
    with mock.patch.object(sched_delivery, "_get_home_target_chat_id", return_value="-100123"), \
         mock.patch.object(sched_delivery, "_get_home_target_thread_id", return_value=None), \
         mock.patch.object(sched_delivery, "_is_known_delivery_platform", return_value=True), \
         mock.patch.object(sched_delivery, "_resolve_origin", return_value=None):
        targets = _resolve_delivery_targets(job)
    platforms = {t["platform"] for t in targets}
    assert BOT_CHAT_PLATFORM in platforms
    assert "telegram" in platforms


# ── preflight ────────────────────────────────────────────────────────────────

def test_preflight_ignores_bot_chat_targets():
    """bot-chat needs no gateway credentials — preflight must not block it."""
    assert _preflight_check_delivery({"id": "j1", "deliver": "bot-chat"}) is None
    assert _preflight_check_delivery({"id": "j1", "deliver": "bot-chat:research"}) is None


def test_preflight_still_blocks_unknown_platforms():
    with mock.patch.object(sched_delivery, "_is_known_delivery_platform", return_value=False):
        err = _preflight_check_delivery({"id": "j1", "deliver": "nonexistent-platform"})
    assert err is not None and "not a known" in err


# ── create-time validation ───────────────────────────────────────────────────

def test_create_validation_rejects_unknown_profile():
    from tools.cronjob_tools import _validate_bot_chat_deliver

    with mock.patch("hermes_cli.profiles.profile_exists", return_value=False):
        err = _validate_bot_chat_deliver("bot-chat:ghost")
    assert err is not None
    assert "machine-local" in err


def test_create_validation_accepts_bare_and_existing():
    from tools.cronjob_tools import _validate_bot_chat_deliver

    assert _validate_bot_chat_deliver("bot-chat") is None
    assert _validate_bot_chat_deliver(None) is None
    assert _validate_bot_chat_deliver("telegram:-100") is None
    with mock.patch("hermes_cli.profiles.profile_exists", return_value=True):
        assert _validate_bot_chat_deliver("bot-chat:research") is None


# ── delivery lane ────────────────────────────────────────────────────────────

def test_deliver_appends_finished_output_as_bot_message(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(sched_delivery, "find_canonical_live_owner", lambda home: None, raising=False)
    monkeypatch.setattr(sched_delivery, "_append_assistant_to_canonical_bot_chat",
                        lambda home, content, delivery_id, profile_name: captured.update(
                            home=home, content=content, delivery_id=delivery_id, profile_name=profile_name))

    err = _deliver_to_bot_chat(
        {"id": "j1", "name": "Daily digest", "execution_id": "run-1"},
        "the output", "",
    )

    assert err is None
    assert captured["content"] == "the output"
    assert captured["profile_name"] == "default"
    assert "Cronjob" not in captured["content"]
    assert "not the user" not in captured["content"]


def test_deliver_named_profile_writes_that_profiles_bot_chat(tmp_path, monkeypatch):
    source = tmp_path / ".hermes"
    target = tmp_path / ".hermes" / "profiles" / "research"
    target.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(source))
    monkeypatch.setattr("hermes_cli.profiles.get_profile_dir", lambda profile: target)
    captured = {}
    monkeypatch.setattr(sched_delivery, "_append_assistant_to_canonical_bot_chat",
                        lambda home, content, delivery_id, profile_name: captured.update(
                            home=home, content=content, profile_name=profile_name))

    assert _deliver_to_bot_chat(
        {"id": "j1", "execution_id": "run-1"}, "out", "research"
    ) is None
    assert captured["home"] == target.resolve()
    assert captured["profile_name"] == "research"


def test_deliver_live_owner_uses_assistant_message_mailbox(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    owner = dict(profile_home=str(tmp_path.resolve()), session_id="bot",
                 lease_id="lease", live_session_id="live")
    monkeypatch.setattr("tools.bot_live_delivery.find_canonical_live_owner", lambda home: owner)
    direct = mock.Mock(side_effect=AssertionError("live owner must receive mailbox delivery"))
    monkeypatch.setattr(sched_delivery, "_append_assistant_to_canonical_bot_chat", direct)

    err = _deliver_to_bot_chat(
        {"id": "j1", "execution_id": "run-1"}, "finished report", ""
    )
    assert err is not None and "queued" in err
    record = next((tmp_path / "runtime" / "bot_live_delivery").glob("*.json"))
    payload = __import__("json").loads(record.read_text())
    assert payload["message"] == "finished report"
    assert payload["mode"] == "assistant_message"
    direct.assert_not_called()


def test_direct_append_creates_one_assistant_only_canonical_message(tmp_path):
    from hermes_state import SessionDB

    delivery_id = "a" * 64
    sched_delivery._append_assistant_to_canonical_bot_chat(
        tmp_path, "scheduled report", delivery_id, profile_name="research"
    )
    # Retry is idempotent: same execution does not duplicate the report.
    sched_delivery._append_assistant_to_canonical_bot_chat(
        tmp_path, "scheduled report", delivery_id, profile_name="research"
    )

    db = SessionDB(db_path=tmp_path / "state.db", read_only=True)
    try:
        row = db.get_session_by_title("Bot Chat")
        assert row is not None and row["hidden"]
        messages = db.get_messages_as_conversation(row["id"])
    finally:
        db.close()
    assert [(m["role"], m["content"]) for m in messages] == [
        ("assistant", "scheduled report")
    ]


def test_deliver_direct_write_failure_returns_error(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(sched_delivery, "_append_assistant_to_canonical_bot_chat",
                        mock.Mock(side_effect=RuntimeError("disk unavailable")))
    err = _deliver_to_bot_chat({"id": "j1", "execution_id": "run"}, "out", "")
    assert err is not None and "disk unavailable" in err


# ── delivery-targets listing (UI pickers) ────────────────────────────────────

def test_delivery_targets_include_local_profiles():
    with mock.patch("hermes_cli.profiles.list_profile_names",
                    return_value=["default", "research"]):
        targets = sched_delivery.cron_delivery_targets()
    ids = [t["id"] for t in targets]
    assert f"{BOT_CHAT_PLATFORM}:default" in ids
    assert f"{BOT_CHAT_PLATFORM}:research" in ids
    bot_chat_entries = [t for t in targets if t["id"].startswith(BOT_CHAT_PLATFORM)]
    # No gateway home channel needed for bot-chat targets.
    assert all(t["home_target_set"] for t in bot_chat_entries)
