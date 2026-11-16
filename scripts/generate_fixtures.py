from __future__ import annotations

import argparse
from pathlib import Path

SOLIDITY_FIXTURE = '''pragma solidity ^0.8.20;
contract VulnerableFixture {
    function usesTxOrigin() public view returns (bool) {
        return tx.origin == msg.sender;
    }
}
'''

PYTHON_UNSAFE_FIXTURE = '''api_key = "supersecretvalue123456"
import pickle
data = pickle.loads(b"...")
'''

PYTHON_SAFE_FIXTURE = '''def add(left: int, right: int) -> int:
    return left + right
'''


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"Created: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="tests/fixtures")
    args = parser.parse_args()
    output = Path(args.output)
    write_file(output / "vulnerable_contract.sol", SOLIDITY_FIXTURE)
    write_file(output / "unsafe_python.py", PYTHON_UNSAFE_FIXTURE)
    write_file(output / "safe_python.py", PYTHON_SAFE_FIXTURE)


if __name__ == "__main__":
    main()
