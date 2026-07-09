class AnchoreError(Exception):
    """Base class for errors safe to expose at the MCP boundary."""

    def __init__(self, user_message: str) -> None:
        self.user_message = user_message
        super().__init__(user_message)

    def __str__(self) -> str:
        return self.user_message


class AnchoreConfigurationError(AnchoreError):
    pass


class AnchoreHttpError(AnchoreError):
    def __init__(self, status: int, user_message: str) -> None:
        self.status = status
        super().__init__(user_message)


class AnchoreInvalidResponseError(AnchoreError):
    pass


class AnchoreNetworkError(AnchoreError):
    pass


class AnchoreTimeoutError(AnchoreError):
    def __init__(self, phase: str) -> None:
        self.phase = phase
        super().__init__("Anchore request timed out")


class AnchoreResponseTooLargeError(AnchoreError):
    def __init__(self, observed: int, max: int) -> None:
        self.observed = observed
        self.max = max
        super().__init__("Anchore response exceeded the configured size limit")


class EnumerationIncompleteError(AnchoreError):
    pass


class TrustEvidenceError(AnchoreError):
    pass
