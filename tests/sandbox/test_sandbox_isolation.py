"""Sandbox isolation regression tests for BlueStrix defensive posture."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"
POLICY = ROOT / "policies" / "SANDBOX_RULES.yaml"


def _compose_text() -> str:
    assert COMPOSE.is_file(), "docker-compose.yml must exist"
    return COMPOSE.read_text(encoding="utf-8")


def _policy() -> dict:
    assert POLICY.is_file(), "policies/SANDBOX_RULES.yaml must exist"
    data = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_docker_compose_exists() -> None:
    assert COMPOSE.is_file()


def test_no_docker_socket_mount() -> None:
    text = _compose_text()
    assert "/var/run/docker.sock" not in text
    assert "docker.sock" not in text


def test_no_privileged_container() -> None:
    text = _compose_text()
    # Allow commenting about privileged, but not enabling it
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "privileged: true" not in stripped
        assert "privileged:true" not in stripped.replace(" ", "")


def test_scanner_non_root_user() -> None:
    text = _compose_text()
    assert 'user: "10001:10001"' in text or "user: '10001:10001'" in text or "user: 10001:10001" in text


def test_scanner_network_mode_none() -> None:
    text = _compose_text()
    assert "network_mode: none" in text


def test_scanner_read_only() -> None:
    text = _compose_text()
    assert "read_only: true" in text


def test_scanner_cap_drop_all() -> None:
    text = _compose_text()
    assert "cap_drop:" in text
    assert "- ALL" in text


def test_scanner_no_new_privileges() -> None:
    text = _compose_text()
    assert "no-new-privileges:true" in text


def test_sandbox_policy_exists() -> None:
    assert POLICY.is_file()


def test_policy_sandbox_network_none() -> None:
    policy = _policy()
    docker = policy["sandbox"]["docker"]
    assert docker["network_mode"] == "none"
    microvm = policy["sandbox"]["microvm"]
    assert microvm["network_enabled"] is False


def test_policy_sandbox_non_root() -> None:
    policy = _policy()
    assert policy["sandbox"]["docker"]["user"] == "10001:10001"


def test_policy_sandbox_read_only() -> None:
    policy = _policy()
    assert policy["sandbox"]["docker"]["read_only"] is True
