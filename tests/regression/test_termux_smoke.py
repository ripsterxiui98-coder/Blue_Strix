import subprocess
import sys

from bluestrix.core.models import CheckStatus
from bluestrix.intelligence.assets.wallet import AssetProtectionEngine
from bluestrix.intelligence.verification.engine import VerificationEngine
from bluestrix.security_controls.input_validation import InputValidator
from bluestrix.security_controls.rate_limiter import RateLimiter
from bluestrix.security_controls.secret_redaction import SecretRedactionControl


def test_cli_help_runs():
    result = subprocess.run([sys.executable, "-m", "bluestrix.cli", "--help"], capture_output=True, text=True)
    assert result.returncode == 0


def test_validator_blocks_path_escape():
    validator = InputValidator()
    try:
        validator.validate_path_within_root("../../etc/passwd", root=".")
    except ValueError:
        assert True
    else:
        raise AssertionError("Path escape not blocked")


def test_rate_limiter_enforces_limit():
    limiter = RateLimiter(max_events=1, window_seconds=60)
    assert limiter.allow("client") is True
    assert limiter.allow("client") is False


def test_secret_redaction():
    control = SecretRedactionControl()
    redacted = control.redact_text("api_key = 'supersecretvalue123456'")
    assert "supersecretvalue123456" not in redacted


def test_wallet_validation():
    engine = AssetProtectionEngine()
    finding = engine.analyze_address("0x0000000000000000000000000000000000000000", "evm")
    assert finding.status == CheckStatus.PASS
