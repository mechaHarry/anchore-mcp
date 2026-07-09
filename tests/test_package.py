from importlib.metadata import distribution, version

import anchore_mcp


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
