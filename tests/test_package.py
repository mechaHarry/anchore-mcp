from collections.abc import Iterable
from importlib.metadata import distribution, version
from pathlib import Path, PurePosixPath
import runpy
import shutil
import subprocess
import sys
import tarfile
from types import ModuleType

import anchore_mcp
from anchore_mcp import __main__ as package_main
import pytest
from pytest import MonkeyPatch


def _validated_sdist_members(members: Iterable[tarfile.TarInfo]) -> set[str]:
    root = PurePosixPath("anchore_mcp-4.0.0")
    files: set[str] = set()
    seen: set[str] = set()

    for member in members:
        path = PurePosixPath(member.name)
        assert not path.is_absolute(), f"absolute tar member path is not permitted: {member.name}"
        try:
            relative = path.relative_to(root)
        except ValueError as error:
            raise AssertionError(
                f"tar member is outside the package root: {member.name}"
            ) from error
        assert ".." not in relative.parts, f"parent traversal is not permitted: {member.name}"
        member_path = relative.as_posix()
        assert member_path not in seen, f"duplicate tar member path is not permitted: {member.name}"
        seen.add(member_path)

        if member.isdir():
            continue
        if member.issym() or member.islnk():
            target = PurePosixPath(member.linkname)
            unsafe = target.is_absolute() or ".." in target.parts
            detail = " with unsafe target" if unsafe else ""
            raise AssertionError(f"tar link entries are not permitted{detail}: {member.name}")
        assert member.isfile(), f"non-regular tar member is not permitted: {member.name}"
        files.add(member_path)

    return files


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


def test_sdist_member_validation_rejects_unsafe_symlink() -> None:
    member = tarfile.TarInfo("anchore_mcp-4.0.0/src/anchore_mcp/leak")
    member.type = tarfile.SYMTYPE
    member.linkname = "/etc/passwd"

    with pytest.raises(AssertionError, match="link"):
        _validated_sdist_members([member])


@pytest.mark.parametrize(
    "member_type",
    [tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE],
)
def test_sdist_member_validation_rejects_other_non_regular_entries(member_type: bytes) -> None:
    member = tarfile.TarInfo("anchore_mcp-4.0.0/src/anchore_mcp/leak")
    member.type = member_type
    member.linkname = "README.md"

    with pytest.raises(AssertionError, match="not permitted"):
        _validated_sdist_members([member])


def test_sdist_member_validation_rejects_duplicate_paths() -> None:
    first = tarfile.TarInfo("anchore_mcp-4.0.0/src/anchore_mcp/config.py")
    second = tarfile.TarInfo("anchore_mcp-4.0.0/src/anchore_mcp/config.py")

    with pytest.raises(AssertionError, match="duplicate"):
        _validated_sdist_members([first, second])


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
        members = _validated_sdist_members(archive.getmembers())

    assert members == {
        ".gitignore",
        "LICENSE",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "src/anchore_mcp/__init__.py",
        "src/anchore_mcp/__main__.py",
        "src/anchore_mcp/anchore/__init__.py",
        "src/anchore_mcp/anchore/http.py",
        "src/anchore_mcp/anchore/openapi.py",
        "src/anchore_mcp/anchore/pagination.py",
        "src/anchore_mcp/anchore/retry.py",
        "src/anchore_mcp/anchore/routes.py",
        "src/anchore_mcp/config.py",
        "src/anchore_mcp/domain/__init__.py",
        "src/anchore_mcp/domain/images.py",
        "src/anchore_mcp/domain/resolution.py",
        "src/anchore_mcp/errors.py",
        "src/anchore_mcp/models/__init__.py",
        "src/anchore_mcp/models/common.py",
        "src/anchore_mcp/models/locators.py",
        "src/anchore_mcp/models/results.py",
        "src/anchore_mcp/runtime.py",
        "src/anchore_mcp/security/__init__.py",
        "src/anchore_mcp/security/logging.py",
        "src/anchore_mcp/security/pii.py",
    }
    assert sdist_path.stat().st_size < 100_000
