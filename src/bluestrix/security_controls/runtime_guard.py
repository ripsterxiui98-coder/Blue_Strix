from __future__ import annotations

import os

from bluestrix.core.exceptions import PolicyViolationError
from bluestrix.security_controls.input_validation import InputValidator


class RuntimeGuard:
    FORBIDDEN_ENV_KEYS = {
        "PRIVATE_KEY",
        "MNEMONIC",
        "SEED_PHRASE",
        "RECOVERY_PHRASE",
        "WALLET_SEED",
    }

    def __init__(self, validator: InputValidator | None = None) -> None:
        self.validator = validator or InputValidator()

    def assert_defensive_environment(self) -> None:
        exposed = [key for key in self.FORBIDDEN_ENV_KEYS if os.environ.get(key)]
        if exposed:
            raise PolicyViolationError(
                f"Critical secret environment variables detected: {', '.join(exposed)}"
            )

    def assert_path_within_root(self, path: str, root: str = ".") -> str:
        return self.validator.validate_path_within_root(path, root)

    def assert_safe_output_path(self, path: str, root: str = "reports") -> str:
        from pathlib import Path

        output_root = Path(root).expanduser().resolve()
        output_root.mkdir(parents=True, exist_ok=True)
        return self.validator.validate_path_within_root(path, str(output_root))
