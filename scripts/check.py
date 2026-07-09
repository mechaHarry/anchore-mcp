"""Run the canonical Python quality gate in fail-fast order."""

import subprocess
import sys


COMMANDS = (
    ("ruff", "format", "--check", "."),
    ("ruff", "check", "."),
    ("pyright",),
    (sys.executable, "-m", "build"),
    ("pip-audit",),
    ("pytest", "--cov=anchore_mcp", "--cov-branch", "--cov-fail-under=90"),
)


def main() -> None:
    for command in COMMANDS:
        subprocess.run(list(command), check=True)


if __name__ == "__main__":
    main()
