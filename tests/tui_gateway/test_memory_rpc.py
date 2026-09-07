"""The JSON-RPC memory surface edits the same curated files the agent loads."""

from __future__ import annotations

from pathlib import Path

from hermes_constants import reset_hermes_home_override, set_hermes_home_override
import tui_gateway.server as server


def _call(method, params=None):
    response = server._methods[method](1, params or {})
    assert "error" not in response, response.get("error")
    return response["result"]


def test_memory_methods_registered():
    assert "memory.list" in server._methods
    assert "memory.mutate" in server._methods


def test_memory_rpc_round_trip_uses_curated_store(tmp_path):
    token = set_hermes_home_override(str(tmp_path))
    try:
        initial = _call("memory.list")
        assert [row["id"] for row in initial["targets"]] == ["user", "memory"]
        assert all(row["entries"] == [] for row in initial["targets"])

        added = _call("memory.mutate", {
            "action": "add", "target": "user", "content": "Prefers concise answers."
        })
        user = next(row for row in added["targets"] if row["id"] == "user")
        assert user["entries"] == ["Prefers concise answers."]
        assert (tmp_path / "memories" / "USER.md").read_text() == "Prefers concise answers."

        replaced = _call("memory.mutate", {
            "action": "replace", "target": "user",
            "old_text": "concise", "content": "Prefers concise Spanish answers."
        })
        user = next(row for row in replaced["targets"] if row["id"] == "user")
        assert user["entries"] == ["Prefers concise Spanish answers."]

        removed = _call("memory.mutate", {
            "action": "remove", "target": "user", "old_text": "Spanish"
        })
        user = next(row for row in removed["targets"] if row["id"] == "user")
        assert user["entries"] == []
    finally:
        reset_hermes_home_override(token)


def test_memory_rpc_rejects_bad_target_without_writing(tmp_path):
    token = set_hermes_home_override(str(tmp_path))
    try:
        response = server._methods["memory.mutate"](
            1, {"action": "add", "target": "other", "content": "nope"}
        )
        assert response["error"]["code"] == 5072
        assert not (Path(tmp_path) / "memories" / "MEMORY.md").exists()
    finally:
        reset_hermes_home_override(token)


def test_memory_rpc_is_profile_scoped_and_does_not_leak(monkeypatch, tmp_path):
    launch_home = tmp_path / "homes" / "launch"
    bot_home = tmp_path / "homes" / "radar-ia"
    launch_home.mkdir(parents=True)
    bot_home.mkdir(parents=True)
    monkeypatch.setattr(
        "hermes_cli.profiles.get_profile_dir",
        lambda name: bot_home if name == "radar-ia" else launch_home,
    )

    token = set_hermes_home_override(str(launch_home))
    try:
        _call("memory.mutate", {
            "profile": "radar-ia", "action": "add", "target": "memory",
            "content": "Radar-only durable note.",
        })
        bot = _call("memory.list", {"profile": "radar-ia"})
        launch = _call("memory.list")
    finally:
        reset_hermes_home_override(token)

    bot_memory = next(row for row in bot["targets"] if row["id"] == "memory")
    launch_memory = next(row for row in launch["targets"] if row["id"] == "memory")
    assert bot_memory["entries"] == ["Radar-only durable note."]
    assert launch_memory["entries"] == []
    assert (bot_home / "memories" / "MEMORY.md").read_text() == "Radar-only durable note."
    assert not (launch_home / "memories" / "MEMORY.md").exists()
