"""BlueStrix plugin system — defensive, sandboxed, evidence-based rules."""

from bluestrix.plugins.loader import PluginLoader, load_plugins_from_directory
from bluestrix.plugins.registry import RuleRegistry
from bluestrix.plugins.rules import SecurityRule, rule_from_dict
from bluestrix.plugins.sandbox import SandboxViolation, run_in_sandbox
from bluestrix.plugins.signing import verify_rule_pack_signature

__all__ = [
    "PluginLoader",
    "RuleRegistry",
    "SecurityRule",
    "SandboxViolation",
    "load_plugins_from_directory",
    "rule_from_dict",
    "run_in_sandbox",
    "verify_rule_pack_signature",
]
