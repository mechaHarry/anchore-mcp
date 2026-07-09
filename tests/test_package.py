from importlib.metadata import distribution, version
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tarfile
from types import ModuleType

import anchore_mcp
from anchore_mcp import __main__ as package_main
from pytest import MonkeyPatch


def test_package_and_distribution_versions_match_release() -> None:
    assert anchore_mcp.__version__ == "4.0.0"
    assert version("anchore-mcp") == "4.0.0"


def test_console_entrypoint_targets_main() -> None:
    entry_points = distribution("anchore-mcp").entry_points
    console_script = next(
        entry_point
        for entry_point in entry_points
        if entry_point.group == "console_scripts" and entry_point.name == "anchore-mcp"
    )

    assert console_script.value == "anchore_mcp.__main__:main"


def test_main_runs_server(monkeypatch: MonkeyPatch) -> None:
    run_calls: list[None] = []
    fake_server = ModuleType("anchore_mcp.server")
    setattr(fake_server, "run", lambda: run_calls.append(None))
    monkeypatch.setitem(sys.modules, "anchore_mcp.server", fake_server)

    package_main.main()

    assert run_calls == [None]


def test_module_guard_runs_server(monkeypatch: MonkeyPatch) -> None:
    run_calls: list[None] = []
    fake_server = ModuleType("anchore_mcp.server")
    setattr(fake_server, "run", lambda: run_calls.append(None))
    monkeypatch.setitem(sys.modules, "anchore_mcp.server", fake_server)
    main_path = Path(package_main.__file__)

    runpy.run_path(str(main_path), run_name="__main__")

    assert run_calls == [None]


def test_sdist_contains_only_allowlisted_distribution_files(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None
    subprocess.run(
        [
            uv,
            "build",
            "--sdist",
            "--no-build-isolation",
            "--out-dir",
            str(tmp_path),
        ],
        check=True,
    )
    (sdist_path,) = tmp_path.glob("*.tar.gz")

    with tarfile.open(sdist_path, mode="r:gz") as archive:
        members = {
            Path(member.name).relative_to("anchore_mcp-4.0.0").as_posix()
            for member in archive.getmembers()
            if member.isfile()
        }

    assert members == {
        ".gitignore",
        "LICENSE",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "src/anchore_mcp/__init__.py",
        "src/anchore_mcp/__main__.py",
        "src/anchore_mcp/config.py",
        "src/anchore_mcp/errors.py",
        "src/anchore_mcp/models/__init__.py",
        "src/anchore_mcp/models/common.py",
        "src/anchore_mcp/models/locators.py",
        "src/anchore_mcp/models/results.py",
    }
    assert sdist_path.stat().st_size < 100_000
