"""Firecracker microVM configuration regression tests."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VM_CONFIG = ROOT / "infra" / "firecracker" / "vm_config.json"


def _load_config() -> dict:
    assert VM_CONFIG.is_file(), "infra/firecracker/vm_config.json must exist"
    data = json.loads(VM_CONFIG.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_vm_config_exists() -> None:
    assert VM_CONFIG.is_file()


def test_vm_config_json_valid() -> None:
    cfg = _load_config()
    assert "machine-config" in cfg
    assert "drives" in cfg


def test_network_interfaces_empty() -> None:
    cfg = _load_config()
    interfaces = cfg.get("network-interfaces", [])
    assert interfaces == [], "Firecracker network-interfaces must be empty"


def test_mem_size_mib_max_512() -> None:
    cfg = _load_config()
    mem = cfg["machine-config"]["mem_size_mib"]
    assert isinstance(mem, int)
    assert mem <= 512
    assert mem > 0


def test_vcpu_count_max_1() -> None:
    cfg = _load_config()
    vcpus = cfg["machine-config"]["vcpu_count"]
    assert isinstance(vcpus, int)
    assert vcpus <= 1
    assert vcpus >= 1


def test_rootfs_drive_present() -> None:
    cfg = _load_config()
    drives = cfg["drives"]
    assert isinstance(drives, list) and len(drives) >= 1
    root_drives = [d for d in drives if d.get("drive_id") == "rootfs"]
    assert root_drives, "rootfs drive_id must exist"


def test_rootfs_is_root_device() -> None:
    cfg = _load_config()
    root_drives = [d for d in cfg["drives"] if d.get("drive_id") == "rootfs"]
    assert root_drives
    assert root_drives[0].get("is_root_device") is True
