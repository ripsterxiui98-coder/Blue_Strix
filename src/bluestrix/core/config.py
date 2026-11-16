from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from bluestrix.core.exceptions import ConfigurationError

DEFAULT_CONFIG_PATH = Path("config/bluestrix.yaml")


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigurationError(f"Configuration file not found: {config_path}")

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML configuration: {exc}") from exc

    if not isinstance(config, dict):
        raise ConfigurationError("Configuration root must be a mapping")

    required_sections = ("version", "mode", "policy", "scope")
    missing = [section for section in required_sections if section not in config]
    if missing:
        raise ConfigurationError(f"Missing configuration sections: {', '.join(missing)}")

    if config.get("mode") != "defensive":
        raise ConfigurationError("BlueStrix v8 must start in defensive mode")

    if config.get("default_execution") != "restricted":
        raise ConfigurationError("default_execution must be restricted")

    return config
