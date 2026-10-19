"""Kalıcı yapılandırma (seçilen strateji / operatör / WAN arayüzü) ve durum."""

from __future__ import annotations

import json

from . import paths

DEFAULTS = {
    "operator": "auto",     # auto | turk-telekom | superonline | vodafone | ...
    "strategy": "turk-telekom",
    "wan_iface": None,       # None = her açılışta otomatik tespit
    "with_quic": True,
}


def load() -> dict:
    cfg = dict(DEFAULTS)
    try:
        cfg.update(json.loads(paths.config_file().read_text()))
    except (FileNotFoundError, ValueError):
        pass
    return cfg


def save(cfg: dict) -> None:
    paths.config_file().write_text(json.dumps(cfg, indent=2) + "\n")


def write_state(state: dict) -> None:
    """Çalışma anı durumu (/run/byerte/state.json) — durum komutu okur."""
    try:
        paths.state_file().write_text(json.dumps(state, indent=2) + "\n")
    except OSError:
        pass


def read_state() -> dict:
    try:
        return json.loads(paths.state_file().read_text())
    except (FileNotFoundError, ValueError):
        return {}
