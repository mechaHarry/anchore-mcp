def main() -> None:
    from anchore_mcp.server import run  # pyright: ignore[reportMissingImports, reportUnknownVariableType]

    run()


if __name__ == "__main__":
    main()
