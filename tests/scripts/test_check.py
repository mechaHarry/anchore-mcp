import importlib.util
from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest


def _load_check_module() -> ModuleType:
    path = Path(__file__).parents[2] / "scripts" / "check.py"
    spec = importlib.util.spec_from_file_location("anchore_mcp_check", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = _load_check_module()


EXPECTED_COMMANDS = [
    ["ruff", "format", "--check", "."],
    ["ruff", "check", "."],
    ["pyright"],
    [sys.executable, "-m", "build"],
    ["pip-audit"],
    ["pytest", "--cov=anchore_mcp", "--cov-branch", "--cov-fail-under=90"],
]


def test_check_runs_six_stages_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def record(command: list[str], *, check: bool) -> None:
        assert check is True
        calls.append(command)

    monkeypatch.setattr(check.subprocess, "run", record)

    check.main()

    assert calls == EXPECTED_COMMANDS


def test_check_stops_after_first_failed_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fail_typecheck(command: list[str], *, check: bool) -> None:
        assert check is True
        calls.append(command)
        if command == ["pyright"]:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(check.subprocess, "run", fail_typecheck)

    with pytest.raises(subprocess.CalledProcessError):
        check.main()

    assert calls == EXPECTED_COMMANDS[:3]


def test_parallel_coverage_data_files_are_ignored() -> None:
    root = Path(__file__).parents[2]
    patterns = (root / ".gitignore").read_text().splitlines()

    assert ".coverage" in patterns
    assert ".coverage.*" in patterns
