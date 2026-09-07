"""Curated built-in memory over the TUI JSON-RPC surface.

This is deliberately the same MEMORY.md / USER.md store the agent injects into
future sessions.  It is not a dashboard-side mirror and it does not attempt to
invent a generic CRUD surface over third-party semantic-memory providers.
"""

from __future__ import annotations

from .method_ctx import HandlerRegistry, bind_module

_registry = HandlerRegistry()
method = _registry.method

_E_MEMORY = 5071
_E_MEMORY_ARG = 5072


def _memory_payload(store) -> dict:
    from hermes_cli.config import load_config

    cfg = load_config() or {}
    memory_cfg = cfg.get("memory") if isinstance(cfg, dict) else {}
    provider = ""
    if isinstance(memory_cfg, dict):
        provider = str(memory_cfg.get("provider") or "").strip()

    def target_payload(target: str, label: str) -> dict:
        entries = list(store._entries_for(target))
        # MemoryStore keeps the delimiter at module scope; calculate the same
        # budget without relying on a class attribute.
        from tools.memory_tool_store import ENTRY_DELIMITER
        used = len(ENTRY_DELIMITER.join(entries))
        return {
            "id": target,
            "label": label,
            "enabled": bool(store.target_enabled(target)),
            "entries": entries,
            "used": used,
            "limit": int(store._char_limit(target)),
        }

    return {
        "provider": provider,
        "targets": [
            target_payload("user", "User profile"),
            target_payload("memory", "Agent notes"),
        ],
    }


def _load_store():
    from tools.memory_tool import load_on_disk_store

    return load_on_disk_store()


@method("memory.list")
@_registry.profile_scoped
def _(rid, params: dict) -> dict:
    try:
        return _ok(rid, _memory_payload(_load_store()))
    except Exception as exc:
        return _err(rid, _E_MEMORY, str(exc))


@method("memory.mutate")
@_registry.profile_scoped
def _(rid, params: dict) -> dict:
    action = str(params.get("action") or "").strip().lower()
    target = str(params.get("target") or "").strip().lower()
    content = str(params.get("content") or "")
    old_text = str(params.get("old_text") or "")
    if action not in {"add", "replace", "remove"}:
        return _err(rid, _E_MEMORY_ARG, "action must be add, replace, or remove")
    if target not in {"memory", "user"}:
        return _err(rid, _E_MEMORY_ARG, "target must be memory or user")

    try:
        store = _load_store()
        if not store.target_enabled(target):
            return _err(rid, _E_MEMORY_ARG, f"Built-in {target} memory is disabled for this profile")
        if action == "add":
            result = store.add(target, content)
        elif action == "replace":
            result = store.replace(target, old_text, content)
        else:
            result = store.remove(target, old_text)
        if not result.get("success"):
            return _err(rid, _E_MEMORY_ARG, str(result.get("error") or "Memory write failed"))
        return _ok(rid, {**_memory_payload(store), "mutation": result})
    except Exception as exc:
        return _err(rid, _E_MEMORY, str(exc))


def register(server) -> None:
    bind_module(globals(), server, skip=("_",))
