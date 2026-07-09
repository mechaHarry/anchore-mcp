# Python FastMCP Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Node/TypeScript MCP with a Python 3.12, `uv`-managed, FastMCP 3.4.3 stdio server that preserves the eight Anchore capabilities while adopting typed inputs, structured results, async connection reuse, and stronger resource bounds.

**Architecture:** Build the Python implementation beside the active TypeScript server. Thin FastMCP adapters call a framework-independent domain core; one lifespan-owned `httpx.AsyncClient` provides bounded request-scoped retries and streaming limits. Cut over only after semantic, protocol, security, lifecycle, and performance gates pass, then remove Node artifacts behind an explicit dirty-file approval checkpoint.

**Tech Stack:** Python 3.12, uv, FastMCP 3.4.3, Pydantic 2, httpx with HTTP/2, pytest, pytest-asyncio, respx, Hypothesis, Ruff, Pyright, build, pip-audit.

---

## File Map

Create these production areas:

- `src/anchore_mcp/__init__.py` — package version.
- `src/anchore_mcp/__main__.py` — console entrypoint only.
- `src/anchore_mcp/server.py` — FastMCP construction and eight registrations.
- `src/anchore_mcp/runtime.py` — lifespan-owned client, cache, and task cleanup.
- `src/anchore_mcp/config.py` — lazy environment parsing.
- `src/anchore_mcp/errors.py` — safe internal error taxonomy.
- `src/anchore_mcp/models/` — locators, context, and capability results.
- `src/anchore_mcp/anchore/` — routes, retry, HTTP, pagination, and OpenAPI.
- `src/anchore_mcp/domain/` — evidence, resolution, selection, policy, vulnerabilities, reports, and handoff.
- `src/anchore_mcp/tools/` — thin FastMCP adapters, one module per tool.
- `src/anchore_mcp/security/` — PII masking and stderr redaction.
- `scripts/check.py` — shell-free canonical quality gate.

Create tests under `tests/unit/`, `tests/http/`, `tests/mcp/`, `tests/property/`, `tests/runtime/`, `tests/security/`, `tests/semantic/`, and `tests/fixtures/semantic/`. All fixture hosts use `.example`; all vulnerability IDs use `CVE-2099-*`; no customer or company identifiers may enter fixtures.

## Task 1: Scaffold the Locked Python Package

**Files:**
- Create: `pyproject.toml`
- Create: `.python-version`
- Create: `src/anchore_mcp/__init__.py`
- Create: `src/anchore_mcp/__main__.py`
- Create: `tests/test_package.py`
- Modify: `.gitignore`
- Generate: `uv.lock`

- [ ] **Step 1: Write the failing package metadata test**

```python
from importlib.metadata import entry_points, version

import anchore_mcp


def test_package_version_and_console_script() -> None:
    assert anchore_mcp.__version__ == "4.0.0"
    assert version("anchore-mcp") == "4.0.0"
    scripts = {entry.name: entry.value for entry in entry_points(group="console_scripts")}
    assert scripts["anchore-mcp"] == "anchore_mcp.__main__:main"
```

- [ ] **Step 2: Run the test and verify the package does not exist**

Run: `uv run pytest tests/test_package.py -q`

Expected: FAIL with `ModuleNotFoundError: No module named 'anchore_mcp'`.

- [ ] **Step 3: Add locked project metadata and the minimal package**

Use this project shape in `pyproject.toml`:

```toml
[build-system]
requires = ["hatchling==1.27.0"]
build-backend = "hatchling.build"

[project]
name = "anchore-mcp"
version = "4.0.0"
requires-python = ">=3.12,<3.13"
dependencies = [
  "fastmcp==3.4.3",
  "httpx[http2]>=0.28.1,<0.29",
  "pydantic>=2.11,<3",
]

[project.scripts]
anchore-mcp = "anchore_mcp.__main__:main"

[dependency-groups]
dev = [
  "build>=1.3,<2",
  "hatchling==1.27.0",
  "hypothesis>=6.135,<7",
  "pip-audit>=2.9,<3",
  "pyright>=1.1.403,<2",
  "pytest>=9.0.3,<10",
  "pytest-asyncio>=1.0,<2",
  "pytest-cov>=6.2,<7",
  "respx>=0.22,<0.23",
  "ruff>=0.12,<0.13",
]

[tool.hatch.build.targets.wheel]
packages = ["src/anchore_mcp"]

[tool.hatch.build.targets.sdist]
ignore-vcs = true
include = ["/LICENSE", "/README.md", "/pyproject.toml", "/src/anchore_mcp"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
addopts = "--strict-markers"
markers = ["live: requires an explicitly configured Anchore deployment", "performance: bounded performance smoke tests"]

[tool.coverage.run]
branch = true
source = ["anchore_mcp"]

[tool.coverage.report]
fail_under = 90

[tool.ruff]
target-version = "py312"
line-length = 100

[tool.pyright]
pythonVersion = "3.12"
typeCheckingMode = "strict"
include = ["src", "tests", "scripts"]
```

Set `.python-version` to `3.12`. Set `src/anchore_mcp/__init__.py` to `__version__ = "4.0.0"`. In `__main__.py`, import `run` from `anchore_mcp.server` inside `main()` so importing package metadata never starts the server.

- [ ] **Step 4: Extend ignores for Python-generated state**

Add `.venv/`, `.pytest_cache/`, `.ruff_cache/`, `.hypothesis/`, `.coverage`, `htmlcov/`, `build/`, `*.egg-info/`, and `__pycache__/`. Retain `dist/` because both TypeScript and Python builds generate it during the transition.

- [ ] **Step 5: Resolve and verify the lock**

Run: `uv lock && uv sync --frozen --all-groups && uv run pytest tests/test_package.py -q`

Expected: lock and sync succeed; the focused test passes.

- [ ] **Step 6: Commit only Python scaffold files**

```bash
git add pyproject.toml uv.lock .python-version .gitignore src/anchore_mcp tests/test_package.py
git commit -S -m "chore: scaffold Python uv project"
```

Do not stage the existing `package.json` modification or `pnpm-workspace.yaml`.

## Task 2: Add Typed Locators, Results, Lazy Configuration, and Safe Errors

**Files:**
- Create: `src/anchore_mcp/models/common.py`
- Create: `src/anchore_mcp/models/locators.py`
- Create: `src/anchore_mcp/models/results.py`
- Create: `src/anchore_mcp/models/__init__.py`
- Create: `src/anchore_mcp/config.py`
- Create: `src/anchore_mcp/errors.py`
- Create: `tests/unit/models/test_locators.py`
- Create: `tests/unit/models/test_results.py`
- Create: `tests/unit/test_config.py`

- [ ] **Step 1: Write failing locator and secret-safety tests**

```python
import pytest
from pydantic import TypeAdapter, ValidationError

from anchore_mcp.config import load_connection
from anchore_mcp.models.locators import ImageLocator, PolicyImageLocator


def test_locator_union_rejects_mixed_states() -> None:
    adapter = TypeAdapter(ImageLocator)
    with pytest.raises(ValidationError):
        adapter.validate_python({"kind": "digest", "digest": "sha256:abc", "reference": "r/x:t"})


def test_repository_locator_is_policy_only() -> None:
    repository = {"kind": "repository", "registry": "registry.example", "repository": "team/app"}
    TypeAdapter(PolicyImageLocator).validate_python(repository)
    with pytest.raises(ValidationError):
        TypeAdapter(ImageLocator).validate_python(repository)


def test_connection_repr_never_contains_token() -> None:
    connection = load_connection({"ANCHORE_URL": "https://anchore.example", "ANCHORE_TOKEN": "secret-value"})
    assert "secret-value" not in repr(connection)
    assert "secret-value" not in str(connection.model_dump())
```

- [ ] **Step 2: Run focused tests and verify imports fail**

Run: `uv run pytest tests/unit/models tests/unit/test_config.py -q`

Expected: FAIL because the models and loader are absent.

- [ ] **Step 3: Implement discriminated locator models and common output models**

```python
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field


class DigestLocator(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["digest"]
    digest: Annotated[str, Field(min_length=1, max_length=1024)]


class ReferenceLocator(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["reference"]
    reference: Annotated[str, Field(min_length=1, max_length=1024)]


class RepositoryLocator(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["repository"]
    registry: Annotated[str, Field(min_length=1, max_length=255)]
    repository: Annotated[str, Field(min_length=1, max_length=1024)]


ImageLocator = Annotated[DigestLocator | ReferenceLocator, Field(discriminator="kind")]
PolicyImageLocator = Annotated[
    DigestLocator | ReferenceLocator | RepositoryLocator,
    Field(discriminator="kind"),
]
```

Define `DeploymentContext`, `EnumerationState`, `SelectedImage`, and one result model for each of the eight tools. Use `pydantic.JsonValue` for raw evidence. Every success result contains context and warnings; list/selection results contain completeness; large payload results contain byte counts. Configure aliases for handoff `handoffVersion`, `generatedAt`, `imageDigest`, and `totalSizeBytes`.

- [ ] **Step 4: Implement clamped lazy environment parsing**

Implement `load_connection(env: Mapping[str, str] | None = None) -> AnchoreConnection` with `SecretStr`, HTTPS-only validation, trailing-slash normalization, blank account to `None`, `v2` default, and retry bounds: retries 0–10, delay values 0–300,000 ms, and base not greater than max. Define `connection_snapshot()` that omits the token and username.

Define safe exception classes with public codes and messages only: `AnchoreConfigurationError`, `AnchoreHttpError`, `AnchoreInvalidResponseError`, `AnchoreNetworkError`, `AnchoreTimeoutError`, `AnchoreResponseTooLargeError`, `EnumerationIncompleteError`, and `TrustEvidenceError`. Never include causes in `__str__`.

- [ ] **Step 5: Run model, config, lint, and type gates**

Run: `uv run pytest tests/unit/models tests/unit/test_config.py -q && uv run ruff check src/anchore_mcp/models src/anchore_mcp/config.py src/anchore_mcp/errors.py tests/unit/models tests/unit/test_config.py && uv run pyright`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/anchore_mcp/models src/anchore_mcp/config.py src/anchore_mcp/errors.py tests/unit/models tests/unit/test_config.py
git commit -S -m "feat: add typed Anchore contracts"
```

## Task 3: Add Versioned Routes and Request-Scoped Backoff

**Files:**
- Create: `src/anchore_mcp/anchore/__init__.py`
- Create: `src/anchore_mcp/anchore/routes.py`
- Create: `src/anchore_mcp/anchore/retry.py`
- Create: `tests/unit/anchore/test_routes.py`
- Create: `tests/unit/anchore/test_retry.py`

- [ ] **Step 1: Write failing route and backoff tests**

```python
from datetime import UTC, datetime

from anchore_mcp.anchore.retry import backoff_seconds, parse_retry_after
from anchore_mcp.anchore.routes import image_sbom_route, image_vulnerabilities_route
from anchore_mcp.config import RetryPolicy


def test_v2_paths_encode_digest_and_use_verified_segments() -> None:
    assert image_vulnerabilities_route("v2", "sha256:a/b") == "/v2/images/sha256%3Aa%2Fb/vuln/all"
    assert image_sbom_route("v2", "sha256:a/b", "spdx") == "/v2/images/sha256%3Aa%2Fb/sboms/spdx-json"


def test_retry_after_http_date_and_full_jitter_are_bounded() -> None:
    now = datetime(2099, 1, 1, tzinfo=UTC)
    assert parse_retry_after("Mon, 01 Jan 2099 00:00:05 GMT", now=now, max_delay_s=8) == 5
    policy = RetryPolicy(max_retries=2, base_delay_ms=300, max_delay_ms=8000)
    assert backoff_seconds(1, policy, random_value=0.5) == 0.3
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/unit/anchore/test_routes.py tests/unit/anchore/test_retry.py -q`

Expected: FAIL because route and retry functions are absent.

- [ ] **Step 3: Implement route builders with one-segment quoting**

Provide `images_list_route`, `image_tag_summaries_route`, `image_vulnerabilities_route`, `image_sbom_route`, `image_by_digest_route`, `image_policy_check_route`, `openapi_route`, and `image_full_tag_query_key`. Call `urllib.parse.quote(digest, safe="")`; return paths only and never concatenate user query strings. Preserve v2 `full_tag`, `/vuln/all`, and plural `/sboms/`; preserve documented v1 forms.

- [ ] **Step 4: Implement retry primitives**

```python
TRANSIENT_HTTP_STATUSES = frozenset({429, 502, 503, 504})


def backoff_seconds(attempt_index: int, policy: RetryPolicy, *, random_value: float, retry_after: float | None = None) -> float:
    cap = policy.max_delay_ms / 1000
    if retry_after is not None:
        return min(cap, max(0.0, retry_after))
    exponential = min(cap, policy.base_delay_ms / 1000 * (2**attempt_index))
    return exponential * min(1.0, max(0.0, random_value))
```

Parse nonnegative integer seconds and IMF-fixdate values relative to an injected UTC clock. Clamp every valid `Retry-After` to the configured cap for all transient statuses. Let `asyncio.CancelledError` propagate from sleep.

- [ ] **Step 5: Verify and commit**

Run: `uv run pytest tests/unit/anchore/test_routes.py tests/unit/anchore/test_retry.py -q`

Expected: PASS.

```bash
git add src/anchore_mcp/anchore tests/unit/anchore/test_routes.py tests/unit/anchore/test_retry.py
git commit -S -m "feat: add Anchore routes and backoff"
```

## Task 4: Build the Bounded Async HTTP Client

**Files:**
- Create: `src/anchore_mcp/anchore/http.py`
- Create: `tests/http/test_anchore_http.py`

- [ ] **Step 1: Write failing HTTP safety tests**

```python
import httpx
import pytest

from anchore_mcp.anchore.http import AnchoreHttpClient
from anchore_mcp.errors import AnchoreResponseTooLargeError


@pytest.mark.asyncio
async def test_stream_limit_applies_to_decoded_bytes() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"value":"1234567890"}')

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        service = AnchoreHttpClient(client)
        with pytest.raises(AnchoreResponseTooLargeError):
            await service.get_json(connection(), "/v2/images", max_response_bytes=8)


@pytest.mark.asyncio
async def test_read_timeout_is_not_retried() -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(Exception):
            await AnchoreHttpClient(client).get_json(connection(), "/v2/images", max_response_bytes=100)
    assert calls == 1
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/http/test_anchore_http.py -q`

Expected: FAIL because HTTP and runtime types are absent.

- [ ] **Step 3: Implement streaming GET semantics**

Create `JsonResponse(data: JsonValue, byte_length: int, headers: httpx.Headers)`. `get_json()` must apply Basic auth `_api_key`, optional account header, `Accept: application/json`, `follow_redirects=False`, and structured `params`. Use `async with client.stream()` plus `response.aiter_bytes()`; check `len(buffer) + len(chunk)` before extending. Empty bodies become `{}`. Decode UTF-8 JSON only after the bound passes. Never return response text in errors.

Retry only `httpx.ConnectError`, `httpx.ConnectTimeout`, and transient statuses while attempts remain. Do not retry `ReadTimeout`, `PoolTimeout`, invalid JSON, size errors, redirects, auth failures, or trust errors. Close the response before a cancellation-aware sleep.

- [ ] **Step 4: Complete the HTTP matrix**

Add tests for account omission, structured query encoding, 302 rejection, safe 401/403/404/5xx messages, Unicode byte length, empty JSON, invalid JSON, gzip expansion, 503 then success, bounded Retry-After seconds/date, exhausted retries, connect retry, cancellation during request/sleep, and cleanup after each failed response.

- [ ] **Step 5: Verify and commit**

Run: `uv run pytest tests/http/test_anchore_http.py -q`

Expected: PASS with no resource warnings.

```bash
git add src/anchore_mcp/anchore/http.py tests/http/test_anchore_http.py
git commit -S -m "feat: add bounded async Anchore client"
```

## Task 5: Add Fail-Closed Pagination and Account-Aware OpenAPI Capabilities

**Files:**
- Create: `src/anchore_mcp/anchore/pagination.py`
- Create: `src/anchore_mcp/anchore/openapi.py`
- Create: `src/anchore_mcp/runtime.py`
- Create: `tests/unit/anchore/test_pagination.py`
- Create: `tests/unit/anchore/test_openapi.py`
- Create: `tests/unit/test_runtime.py`

- [ ] **Step 1: Write failing boundary tests**

```python
def test_off_origin_next_link_is_incomplete() -> None:
    result = validate_next_link("https://anchore.example", "https://evil.example/v2/images?page=2")
    assert result.kind == "incomplete"
    assert result.reason == "off_origin_next_link"


@pytest.mark.asyncio
async def test_openapi_cache_is_single_entry_and_account_aware() -> None:
    cache = OpenApiCache(clock=lambda: 100.0)
    await cache.get(fake_http, connection(account="a"))
    await cache.get(fake_http, connection(account="b"))
    assert cache.size == 1
    assert fake_http.calls == 2
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/unit/anchore/test_pagination.py tests/unit/anchore/test_openapi.py -q`

Expected: FAIL because pagination and OpenAPI modules are absent.

- [ ] **Step 3: Implement bounded pagination**

Define immutable `PageCaps`, `PaginatedRows`, and completeness models. Preserve list caps of 200 pages/50,000 rows and resolution caps of 100 pages/20,000 rows. Support `items`, `images`, and root arrays. Treat malformed, repeated, or off-origin advertised continuation as incomplete rather than complete. Validate stable `total_rows`; stop conservatively on empty pages; report caps explicitly.

- [ ] **Step 4: Implement the one-entry capability cache**

Key cache entries by `(normalized_base_url, api_version, account)` and exclude token material. Use monotonic 600-second expiry, a 6,000,000-byte document cap, an `asyncio.Lock` to prevent fill stampedes, and cardinality exactly one. Failed or cancelled fills do not populate the cache. Capability extraction ignores `$ref`, bounds paths/parameters/name lengths, and trusts v1 repository summary filters only when direct `registry` and `repository` query parameters are present.

- [ ] **Step 5: Implement lifespan-owned runtime after the cache exists**

```python
@dataclass(slots=True)
class Runtime:
    httpx_client: httpx.AsyncClient
    anchore_http: AnchoreHttpClient
    openapi_cache: OpenApiCache
    owned_tasks: set[asyncio.Task[object]]
    closed: bool = False

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for task in tuple(self.owned_tasks):
            task.cancel()
        await asyncio.gather(*self.owned_tasks, return_exceptions=True)
        self.owned_tasks.clear()
        self.openapi_cache.clear()
        await self.httpx_client.aclose()
```

The factory uses `http2=True`, redirects off, 20 total connections, 10 keepalive connections, 30-second keepalive expiry, and connect/pool/write/read timeouts of 10/10/10/60 seconds. It does not read `ANCHORE_*`. Tests prove idempotent close, cache clearing, task cancellation, closed client state, and no environment access during startup.

- [ ] **Step 6: Verify and commit**

Run: `uv run pytest tests/unit/anchore/test_pagination.py tests/unit/anchore/test_openapi.py tests/unit/test_runtime.py -q`

Expected: PASS, including concurrent one-fetch and replacement tests.

```bash
git add src/anchore_mcp/anchore/pagination.py src/anchore_mcp/anchore/openapi.py src/anchore_mcp/runtime.py tests/unit/anchore/test_pagination.py tests/unit/anchore/test_openapi.py tests/unit/test_runtime.py
git commit -S -m "feat: add bounded Anchore enumeration"
```

## Task 6: Add PII Masking and Safe Stderr Logging

**Files:**
- Create: `src/anchore_mcp/security/__init__.py`
- Create: `src/anchore_mcp/security/pii.py`
- Create: `src/anchore_mcp/security/logging.py`
- Create: `tests/security/test_pii.py`
- Create: `tests/security/test_logging.py`

- [ ] **Step 1: Write failing redaction tests**

```python
def test_redaction_precedes_line_cap() -> None:
    secret = "super-secret-token"
    line = f"Authorization: Basic {secret} " + "x" * 1000
    rendered = safe_log_line(line, configured_secrets=(secret,))
    assert secret not in rendered
    assert "[REDACTED]" in rendered
    assert len(rendered.encode("utf-8")) <= 512
    assert "\n" not in rendered


def test_masked_text_warns_without_mutating_structured_evidence() -> None:
    evidence = {"owner": "person@example.test"}
    masked = prepare_text("Contact person@example.test", evidence)
    assert "person@example.test" not in masked.text
    assert masked.structured is evidence
    assert masked.warnings
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/security -q`

Expected: FAIL because security modules are absent.

- [ ] **Step 3: Implement deterministic masking and stderr normalization**

Port email, US-SSN-like, and North-American-phone-like heuristics. Return deduplicated warnings in deterministic order. Redact Basic/Bearer values, authorization headers, token-like query parameters, and configured secrets before replacing control characters and truncating to 512 UTF-8 bytes. Write through a single stderr helper; never use `print()` in production modules.

- [ ] **Step 4: Verify and commit**

Run: `uv run pytest tests/security -q && uv run ruff check src/anchore_mcp/security tests/security`

Expected: PASS.

```bash
git add src/anchore_mcp/security tests/security
git commit -S -m "feat: add PII and log safeguards"
```

## Task 7: Port Bounded Image Evidence and Exact Reference Resolution

**Files:**
- Create: `src/anchore_mcp/domain/__init__.py`
- Create: `src/anchore_mcp/domain/images.py`
- Create: `src/anchore_mcp/domain/resolution.py`
- Create: `tests/unit/domain/test_image_evidence.py`
- Create: `tests/unit/domain/test_reference_resolution.py`
- Create: `tests/property/test_image_evidence_properties.py`

- [ ] **Step 1: Write failing evidence-overflow and resolution tests**

```python
def test_evidence_overflow_never_becomes_no_match() -> None:
    row = {"image_detail": [{"fulltag": f"registry.example/team/app:{index}"} for index in range(65)]}
    evidence = extract_reference_evidence(row)
    assert evidence.complete is False
    assert evidence.reason == "detail_entry_limit"


@pytest.mark.asyncio
async def test_exact_match_plus_incomplete_page_fails_closed() -> None:
    result = await resolve_image_reference(fake_client_with_match_and_cap(), connection(), "registry.example/team/app:1")
    assert result.kind == "incomplete"
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/unit/domain/test_image_evidence.py tests/unit/domain/test_reference_resolution.py -q`

Expected: FAIL because domain image modules are absent.

- [ ] **Step 3: Implement bounded evidence extraction**

Port the current verified limits: 1,024-character references, 64 detail entries, 64 tags per object, 32 normalized references, and 256 scans per row. Validate registry-qualified `repository:tag`, including registry ports and bracketed IPv6. Synthesize a reference only from coherent registry/repository/tag fields in the same object. Count non-string entries against scan budgets. Return `ReferenceEvidence(references, complete, reason)`.

- [ ] **Step 4: Implement exact resolution outcomes**

Define the discriminated outcomes `resolved`, `no_match`, `disambiguation`, and `incomplete`. Query v2 with `full_tag` and v1 with `fulltag`; treat backend filtering as a hint. Dedupe by digest. Bound disambiguation to 50 candidates, eight hints per digest, and 64 hints total. Any evidence or pagination overflow returns `incomplete`, even after a match.

- [ ] **Step 5: Add bounded property coverage**

Use Hypothesis recursive JSON strategies capped at depth six and 100 examples. Assert extraction never raises an unhandled exception, output cardinality never exceeds 32, strings never exceed 1,024, and incomplete evidence cannot produce `resolved` or `no_match`.

- [ ] **Step 6: Verify and commit**

Run: `uv run pytest tests/unit/domain/test_image_evidence.py tests/unit/domain/test_reference_resolution.py tests/property/test_image_evidence_properties.py -q`

Expected: PASS.

```bash
git add src/anchore_mcp/domain tests/unit/domain/test_image_evidence.py tests/unit/domain/test_reference_resolution.py tests/property/test_image_evidence_properties.py
git commit -S -m "feat: resolve image references exactly"
```

## Task 8: Port Fail-Closed Policy Image Selection

**Files:**
- Create: `src/anchore_mcp/domain/selection.py`
- Create: `tests/unit/domain/test_image_selection.py`
- Create: `tests/property/test_timestamp_selection_properties.py`

- [ ] **Step 1: Write failing timestamp-trust tests**

```python
@pytest.mark.asyncio
async def test_missing_timestamp_on_digest_candidate_fails_closed() -> None:
    with pytest.raises(TrustEvidenceError, match="timestamp evidence"):
        await select_image_for_policy(client_with_missing_timestamp(), connection(), reference_locator(), openapi())


@pytest.mark.asyncio
async def test_tied_newest_digests_fail_closed() -> None:
    with pytest.raises(TrustEvidenceError, match="newest image is ambiguous"):
        await select_image_for_policy(client_with_tied_digests(), connection(), repository_locator(), openapi())
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/unit/domain/test_image_selection.py -q`

Expected: FAIL because selection is absent.

- [ ] **Step 3: Implement selection without timestamp guessing**

Digest locators return immediately. Reference selection requires exact evidence and a trusted analysis timestamp for every digest-bearing match. Repository selection uses v2 `/summaries/image-tags` with direct registry/repository filters; v1 remains disabled unless bounded same-origin OpenAPI proves both filters. Ignore digestless rows. Normalize documented ISO strings, epoch seconds, and epoch milliseconds; reject invalid, non-finite, Boolean, and out-of-range values. Ties across digests fail closed.

- [ ] **Step 4: Add timestamp properties and verify**

Assert arbitrary finite numeric and string timestamp inputs either normalize deterministically or raise `TrustEvidenceError`; none may select a digest through fallback ordering.

Run: `uv run pytest tests/unit/domain/test_image_selection.py tests/property/test_timestamp_selection_properties.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/anchore_mcp/domain/selection.py tests/unit/domain/test_image_selection.py tests/property/test_timestamp_selection_properties.py
git commit -S -m "feat: select policy images fail closed"
```

## Task 9: Port Policy Interpretation and Exact Vulnerability Correlation

**Files:**
- Create: `src/anchore_mcp/domain/policy.py`
- Create: `src/anchore_mcp/domain/vulnerabilities.py`
- Create: `tests/unit/domain/test_policy.py`
- Create: `tests/unit/domain/test_vulnerabilities.py`

- [ ] **Step 1: Write failing anti-fuzzy-correlation tests**

```python
def test_generic_id_is_not_vulnerability_evidence() -> None:
    payload = {"gate": "dockerfile", "id": "CVE-2099-0001", "action": "STOP"}
    assert extract_policy_blocking_findings(payload) == ()


def test_package_name_without_version_does_not_correlate() -> None:
    finding = PolicyBlockingFinding(package_name="openssl", package_version=None, source_ref="finding-1")
    vulnerability = NormalizedVulnerability(vulnerability_id=None, package_name="openssl", package_version="1.0")
    assert correlate_blockers((finding,), (vulnerability,)) == ()
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/unit/domain/test_policy.py tests/unit/domain/test_vulnerabilities.py -q`

Expected: FAIL because policy and vulnerability modules are absent.

- [ ] **Step 3: Implement bounded iterative extraction**

Walk hostile JSON iteratively with explicit node, depth, collection, and string bounds. Recognize only supported green/red states and actual blocking action/status/result fields. Treat generic IDs as vulnerability evidence only under a vulnerability gate. Extract supported CVE/GHSA/advisory identifiers from trigger fields. Normalize supported vulnerability wrappers, package identities, fix versions, and path evidence. Deduplicate exact records only.

- [ ] **Step 4: Implement exact correlation**

Correlate on exact case-normalized vulnerability ID or exact `(package_name, installed_version)`. Do not correlate on severity, package name alone, prefix, substring, or fuzzy version. Preserve distinct path evidence.

- [ ] **Step 5: Verify and commit**

Run: `uv run pytest tests/unit/domain/test_policy.py tests/unit/domain/test_vulnerabilities.py -q`

Expected: PASS.

```bash
git add src/anchore_mcp/domain/policy.py src/anchore_mcp/domain/vulnerabilities.py tests/unit/domain/test_policy.py tests/unit/domain/test_vulnerabilities.py
git commit -S -m "feat: correlate exact policy blockers"
```

## Task 10: Build Trust-Sensitive Reports and Remediation Handoff v2

**Files:**
- Create: `src/anchore_mcp/domain/policy_report.py`
- Create: `src/anchore_mcp/domain/handoff.py`
- Create: `tests/unit/domain/test_policy_report.py`
- Create: `tests/unit/domain/test_handoff.py`
- Create: `tests/unit/domain/test_handoff_lifecycle.py`

- [ ] **Step 1: Write failing request-order and concurrency tests**

```python
@pytest.mark.asyncio
async def test_green_policy_skips_vulnerability_request() -> None:
    client = recording_client(policy="green")
    result = await build_policy_blocking_report(client, connection(), digest_locator(), openapi())
    assert result.status == "already_green"
    assert client.paths == ["/v2/images/sha256%3Aabc/check"]


@pytest.mark.asyncio
async def test_handoff_failure_cancels_siblings() -> None:
    client = failing_concurrent_client()
    with pytest.raises(AnchoreHttpError):
        await build_remediation_handoff(client, connection(), digest_locator())
    assert client.running_requests == 0
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/unit/domain/test_policy_report.py tests/unit/domain/test_handoff.py tests/unit/domain/test_handoff_lifecycle.py -q`

Expected: FAIL because orchestrators are absent.

- [ ] **Step 3: Implement policy report sequencing**

Select the image, fetch policy, and return `already_green` when green or unknown without a blocking action. Only then fetch vulnerability evidence up to 20 MiB and correlate exact blockers. Use selected reference as policy tag only when explicit `tag` is absent. Raise `TrustEvidenceError("red policy has no proven vulnerability remediation")` when a non-green policy cannot be joined exactly.

- [ ] **Step 4: Implement structured-concurrency handoff**

Resolve once, then use `asyncio.TaskGroup` for detail and vulnerabilities plus policy when requested. Record decoded byte sizes per evidence entry and total. Emit handoff version `2.0.0`, deterministic injected UTC time, deployment, image digest, and optional policy evidence. On any failure or cancellation, TaskGroup cancels and awaits siblings.

- [ ] **Step 5: Verify and commit**

Run: `uv run pytest tests/unit/domain/test_policy_report.py tests/unit/domain/test_handoff.py tests/unit/domain/test_handoff_lifecycle.py -q`

Expected: PASS; two requests overlap without policy, three overlap with policy, and no task remains after failure.

```bash
git add src/anchore_mcp/domain/policy_report.py src/anchore_mcp/domain/handoff.py tests/unit/domain/test_policy_report.py tests/unit/domain/test_handoff.py tests/unit/domain/test_handoff_lifecycle.py
git commit -S -m "feat: add policy reports and handoff v2"
```

## Task 11: Add the Safe FastMCP Adapter Boundary and First Two Tools

**Files:**
- Create: `src/anchore_mcp/tools/__init__.py`
- Create: `src/anchore_mcp/tools/common.py`
- Create: `src/anchore_mcp/tools/connection_info.py`
- Create: `src/anchore_mcp/tools/list_images.py`
- Create: `tests/unit/tools/test_common.py`
- Create: `tests/unit/tools/test_connection_info.py`
- Create: `tests/unit/tools/test_list_images.py`

- [ ] **Step 1: Write failing adapter tests**

```python
def test_success_result_contains_text_and_structured_content() -> None:
    result = success_result("Listed images", connection_info_result())
    assert result.content[0].text == "Listed images"
    assert result.structured_content["configured"] is True


@pytest.mark.asyncio
async def test_connection_info_missing_env_is_normal_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_connection() -> AnchoreConnection:
        raise AnchoreConfigurationError("Anchore is not configured")

    monkeypatch.setattr("anchore_mcp.tools.connection_info.load_connection", missing_connection)
    result = await anchore_connection_info(fake_context())
    assert result.structured_content["configured"] is False
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/unit/tools/test_common.py tests/unit/tools/test_connection_info.py tests/unit/tools/test_list_images.py -q`

Expected: FAIL because tool adapters are absent.

- [ ] **Step 3: Implement safe result and error translation**

`success_result()` serializes Pydantic with `mode="json", by_alias=True`, masks concise text, and merges deterministic masking warnings. `tool_error()` maps only allowlisted domain/config/HTTP exceptions to `fastmcp.exceptions.ToolError`. Unknown exceptions log a sanitized type name and return `ToolError("Anchore operation failed safely")`; never stringify arbitrary exceptions or evidence.

- [ ] **Step 4: Implement connection and list adapters**

Connection info loads env lazily and returns `configured=False` normally when absent. List images merges bounded pages, applies explicit `fulltag` and `vulnerability_id`, allows at most 32 deployment-advertised `list_query` keys with values at most 4,096 characters, reports rejected keys, and returns completeness explicitly.

- [ ] **Step 5: Verify and commit**

Run: `uv run pytest tests/unit/tools/test_common.py tests/unit/tools/test_connection_info.py tests/unit/tools/test_list_images.py -q`

Expected: PASS.

```bash
git add src/anchore_mcp/tools tests/unit/tools
git commit -S -m "feat: add connection and image list tools"
```

## Task 12: Add the Remaining Six Thin Tool Adapters

**Files:**
- Create: `src/anchore_mcp/tools/image_vulnerabilities.py`
- Create: `src/anchore_mcp/tools/image_sbom.py`
- Create: `src/anchore_mcp/tools/image_policy_check.py`
- Create: `src/anchore_mcp/tools/policy_blocking_vulnerabilities.py`
- Create: `src/anchore_mcp/tools/image_detail.py`
- Create: `src/anchore_mcp/tools/remediation_handoff.py`
- Create: corresponding `tests/unit/tools/test_*.py`

- [ ] **Step 1: Write failing parameterized capability tests**

```python
@pytest.mark.parametrize(
    "tool_name",
    [
        "anchore_image_vulnerabilities",
        "anchore_image_sbom",
        "anchore_image_policy_check",
        "anchore_policy_blocking_vulnerabilities",
        "anchore_image_detail",
        "anchore_remediation_handoff",
    ],
)
@pytest.mark.asyncio
async def test_missing_config_is_safe_tool_error(tool_name: str) -> None:
    with pytest.raises(ToolError) as raised:
        await invoke_adapter(tool_name, env={})
    assert "token" not in str(raised.value).lower()
    assert "traceback" not in str(raised.value).lower()
```

- [ ] **Step 2: Run six focused files and verify failure**

Run: `uv run pytest tests/unit/tools -q`

Expected: FAIL for the six missing modules.

- [ ] **Step 3: Implement vulnerability and SBOM adapters**

Both resolve typed locators through the shared resolver. Vulnerabilities return raw evidence plus decoded size. SBOM maps `normal`, `spdx`, and `cyclonedx` to verified wire formats, defaults to 20,000,000 bytes, permits a positive caller cap up to 100,000,000, and rejects rather than truncates.

- [ ] **Step 4: Implement policy check and image detail adapters**

Policy check keeps locator separate from optional `tag` and `base_digest`. Detail returns raw evidence and size. Both expose concise masked text plus structured content.

- [ ] **Step 5: Implement policy blocker and handoff adapters**

Policy blocker accepts `PolicyImageLocator` and returns only compact proven blockers. Handoff accepts `ImageLocator`, optional policy context, and `include_policy_check=True`; raw evidence remains only in structured content.

- [ ] **Step 6: Verify in two rollback-safe commits**

Run: `uv run pytest tests/unit/tools/test_image_vulnerabilities.py tests/unit/tools/test_image_sbom.py tests/unit/tools/test_image_policy_check.py tests/unit/tools/test_image_detail.py -q`

Expected: PASS.

```bash
git add src/anchore_mcp/tools/image_vulnerabilities.py src/anchore_mcp/tools/image_sbom.py src/anchore_mcp/tools/image_policy_check.py src/anchore_mcp/tools/image_detail.py tests/unit/tools
git commit -S -m "feat: add image evidence tools"
```

Run: `uv run pytest tests/unit/tools/test_policy_blocking_vulnerabilities.py tests/unit/tools/test_remediation_handoff.py -q`

Expected: PASS.

```bash
git add src/anchore_mcp/tools/policy_blocking_vulnerabilities.py src/anchore_mcp/tools/remediation_handoff.py tests/unit/tools
git commit -S -m "feat: add policy blocker and handoff tools"
```

## Task 13: Create the FastMCP Server and Native Contract Tests

**Files:**
- Create: `src/anchore_mcp/server.py`
- Complete: `src/anchore_mcp/__main__.py`
- Create: `tests/mcp/test_server.py`
- Create: `tests/mcp/test_tools.py`
- Create: `tests/semantic/test_capabilities.py`
- Create: synthetic files under `tests/fixtures/semantic/`

- [ ] **Step 1: Write failing in-memory discovery test**

```python
@pytest.mark.asyncio
async def test_server_advertises_exact_native_contract() -> None:
    server = create_server(runtime_factory=fake_runtime_factory)
    async with Client(server) as client:
        tools = await client.list_tools()
    assert {tool.name for tool in tools} == EXPECTED_EIGHT_TOOL_NAMES
    for tool in tools:
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.destructiveHint is False
        assert tool.annotations.openWorldHint is True
```

- [ ] **Step 2: Run tests and verify failure**

Run: `uv run pytest tests/mcp/test_server.py tests/mcp/test_tools.py tests/semantic/test_capabilities.py -q`

Expected: FAIL because `create_server()` is absent.

- [ ] **Step 3: Build the server with lifespan and explicit registrations**

```python
def create_server(*, runtime_factory: RuntimeFactory = create_runtime) -> FastMCP:
    app = FastMCP(name="anchore-mcp", version="4.0.0", lifespan=make_lifespan(runtime_factory))
    register_connection_info(app)
    register_list_images(app)
    register_image_vulnerabilities(app)
    register_image_sbom(app)
    register_image_policy_check(app)
    register_policy_blocking_vulnerabilities(app)
    register_image_detail(app)
    register_remediation_handoff(app)
    return app


def run() -> None:
    create_server().run(transport="stdio")
```

Use `ToolAnnotations(readOnlyHint=True, idempotentHint=True, destructiveHint=False, openWorldHint=True)` on every registration. Do not enable FastMCP payload logging, RetryMiddleware, cache middleware, background tasks, or HTTP transport.

- [ ] **Step 4: Add semantic fixtures before the TypeScript oracle is removed**

Create synthetic fixtures for connection, v1/v2 image lists, unique/ambiguous/incomplete resolution, vulnerabilities, all SBOM formats, green/red policy, exact blockers, image detail, and handoff. Assert capability outcomes and trust decisions, not legacy wrapper text or flat arguments.

- [ ] **Step 5: Verify and commit**

Run: `uv run pytest tests/mcp/test_server.py tests/mcp/test_tools.py tests/semantic/test_capabilities.py -q`

Expected: PASS; discovery needs no credentials and every success contains text plus structured content.

```bash
git add src/anchore_mcp/server.py src/anchore_mcp/__main__.py tests/mcp tests/semantic tests/fixtures/semantic
git commit -S -m "feat: expose eight FastMCP capabilities"
```

## Task 14: Add Stdio, Adversarial, Lifecycle, and Performance Verification

**Files:**
- Create: `tests/mcp/test_stdio.py`
- Create: `tests/property/test_image_references.py`
- Create: `tests/property/test_pagination.py`
- Create: `tests/property/test_anchore_shapes.py`
- Create: `tests/runtime/test_lifecycle.py`
- Create: `tests/runtime/test_performance.py`
- Create: `tests/support/anchore_server.py`

- [ ] **Step 1: Write the real stdio lifecycle test**

```python
@pytest.mark.asyncio
async def test_stdio_discovers_without_credentials_and_exits_cleanly(clean_env: dict[str, str]) -> None:
    transport = StdioTransport(command="uv", args=["run", "--frozen", "anchore-mcp"], env=clean_env)
    async with Client(transport) as client:
        tools = await client.list_tools()
        assert {tool.name for tool in tools} == EXPECTED_EIGHT_TOOL_NAMES
```

Use the official FastMCP transport API resolved by the locked 3.4.3 package. The test fails if stdout has a preamble because JSON-RPC parsing fails. Add an EOF test requiring exit within two seconds and a slow-request cancellation test requiring no surviving process.

- [ ] **Step 2: Add loopback-only synthetic Anchore support**

Implement a stdlib test server bound to `127.0.0.1` on an ephemeral port. It serves only synthetic fixtures, records connection identities and request order, and never logs request authorization. Do not bind to `0.0.0.0` or use a real token.

- [ ] **Step 3: Add adversarial properties**

Bound Hypothesis to 100 deterministic examples. Prove arbitrary references cannot inject paths or queries; foreign/malformed continuations always yield incomplete; hostile nested JSON cannot escape scanner bounds or leak internal exception text; buffers, candidates, hints, and caches never exceed constants.

- [ ] **Step 4: Add lifecycle and concurrency assertions**

Repeat lifespan enter/use/exit 25 times. Assert the client is closed, cache size is zero, owned task set is empty, and no task named with `anchore-mcp` survives. Use events/barriers rather than tight timing to prove two/three handoff requests overlap and vulnerability fetch waits for policy when required.

- [ ] **Step 5: Add generous performance smoke ceilings**

Mark performance tests. Require warm stdio discovery under three seconds, assert sequential requests reuse a connection, and assert bounded container cardinality directly. Use `tracemalloc` only as a supplemental broad ceiling, not the primary leak proof.

- [ ] **Step 6: Verify and commit**

Run: `uv run pytest tests/mcp/test_stdio.py tests/property tests/runtime/test_lifecycle.py -q && uv run pytest -m performance tests/runtime/test_performance.py -q`

Expected: PASS with no leaked tasks, sockets, or subprocesses.

```bash
git add tests/mcp/test_stdio.py tests/property tests/runtime tests/support
git commit -S -m "test: verify stdio security and lifecycle"
```

## Task 15: Add the Canonical Quality Gate and Parallel Python CI

**Files:**
- Create: `scripts/check.py`
- Create: `tests/scripts/test_check.py`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the failing orchestrator-order test**

```python
def test_check_runs_six_stages_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(subprocess, "run", lambda command, check: calls.append(command))
    check.main()
    assert calls == [
        ["ruff", "format", "--check", "."],
        ["ruff", "check", "."],
        ["pyright"],
        [sys.executable, "-m", "build"],
        ["pip-audit"],
        ["pytest", "--cov=anchore_mcp", "--cov-branch", "--cov-fail-under=90"],
    ]
```

- [ ] **Step 2: Run and verify failure**

Run: `uv run pytest tests/scripts/test_check.py -q`

Expected: FAIL because `scripts/check.py` is absent.

- [ ] **Step 3: Implement the no-shell gate**

```python
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
```

Add a test proving `CalledProcessError` stops later commands. Never use `shell=True`.

- [ ] **Step 4: Add Python CI without removing Node CI**

Add a `python-quality` job using `astral-sh/setup-uv`, Python 3.12, `uv sync --frozen --all-groups`, and `uv run python scripts/check.py`. Retain the current Node job until final cutover so both implementations remain independently green.

- [ ] **Step 5: Run the complete gate**

Run: `uv run pytest tests/scripts/test_check.py -q && uv run python scripts/check.py`

Expected: all six stages pass and combined line/branch coverage is at least 90 percent.

- [ ] **Step 6: Commit**

```bash
git add scripts/check.py tests/scripts/test_check.py .github/workflows/ci.yml
git commit -S -m "ci: add locked Python quality gate"
```

## Task 16: Update the Handoff Contract and User Documentation

**Files:**
- Modify: `docs/remediation-handoff-schema.md`
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `env.example`
- Modify: `examples/codex-agent-setup/README.md`
- Modify: `docs/research/anchore-api-notes.md`
- Create: `docs/solutions/integration-issues/2026-07-08-fastmcp-request-scoped-retries-and-stdio-lifecycle.md`
- Modify: `MEMORY.md` only if a promoted entry exists

- [ ] **Step 1: Document handoff 2.0.0 exactly**

Specify structured content with `handoffVersion`, `generatedAt`, `deployment`, `imageDigest`, `totalSizeBytes`, and evidence entries shaped as `{data, sizeBytes}`. Omit the policy entry entirely when disabled. State that it is Anchore evidence, not remediation instruction, and that raw evidence is unmasked.

- [ ] **Step 2: Replace Node launch instructions with uv and typed examples**

Document `uv sync --frozen` and `uv run anchore-mcp`, the same seven `ANCHORE_*` variables, stdio-only transport, one deployment per process, lazy configuration, discriminated locator objects, structured content, and advisory read-only annotations. Use only reserved example values.

- [ ] **Step 3: Update repository guidance and API research**

Replace TypeScript architecture and test commands in `AGENTS.md`. Preserve all route, stdout/stderr, PII, sizing, and fail-closed rules. Add verified FastMCP/httpx learnings to a solution document with existing Compound-style frontmatter; do not fossilize claims until the implementation tests prove them.

- [ ] **Step 4: Search for stale active guidance**

Run: `rg -n 'pnpm|dist/index|node |npm |3\.0\.0|handoffVersion.*1' README.md AGENTS.md env.example examples docs .github`

Expected: every remaining match is historical context or explicitly marked legacy; active setup points to Python 4.0.0.

- [ ] **Step 5: Verify and commit**

Run: `uv run python scripts/check.py && uv run pytest tests/mcp/test_stdio.py -q`

Expected: PASS.

```bash
git add README.md AGENTS.md env.example examples/codex-agent-setup/README.md docs MEMORY.md
git commit -S -m "docs: document Python FastMCP 4.0"
```

## Task 17: Perform the Explicit Node Removal Gate and Final Cutover

**Files:**
- Delete after approval: tracked TypeScript sources and Node build metadata
- Delete after approval: untracked `pnpm-workspace.yaml`
- Modify: `.github/workflows/ci.yml`
- Create: `scripts/smoke_wheel.py`

- [ ] **Step 1: Re-read the dirty state before any deletion**

Run:

```bash
git status --short
git diff -- package.json
sed -n '1,80p' pnpm-workspace.yaml
```

Expected at current state: `package.json` contains the user-owned pnpm 11.9.0 change and `pnpm-workspace.yaml` contains `allowBuilds: esbuild: false`.

- [ ] **Step 2: Stop and obtain explicit destructive approval**

Show the exact current diff and ask whether those user-owned changes are intentionally superseded by the Python-only 4.0.0 cutover. Do not delete, stage, or rewrite either file until the user confirms. If the user wants preservation, commit them separately or move the removal to a clean worktree as directed.

- [ ] **Step 3: Remove the approved Node implementation**

After confirmation, remove `src/**/*.ts`, `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `tsconfig.json`, `vitest.config.ts`, `eslint.config.js`, and `.nvmrc`. Retain `src/anchore_mcp`. Remove the Node CI job so only locked Python quality remains.

- [ ] **Step 4: Prove no active Node dependency remains**

Run:

```bash
git ls-files | rg '(package\.json|pnpm|\.ts$|tsconfig|vitest|eslint\.config)'
rg -n 'pnpm|dist/index|node_modules|typescript|vitest' README.md AGENTS.md env.example examples .github pyproject.toml scripts tests
```

Expected: first command has no output; second has no active runtime or development instructions.

- [ ] **Step 5: Run final clean-room gates**

Run: `uv sync --frozen --all-groups && uv run python scripts/check.py && uv run pytest tests/mcp/test_stdio.py -q && uv build`

Expected: all commands pass; wheel and source distribution are created.

- [ ] **Step 6: Verify the built console script**

Create `scripts/smoke_wheel.py` with an isolated local-wheel transport:

```python
import asyncio
import os
import sys

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

EXPECTED = {
    "anchore_connection_info",
    "anchore_list_images",
    "anchore_image_vulnerabilities",
    "anchore_image_sbom",
    "anchore_image_policy_check",
    "anchore_policy_blocking_vulnerabilities",
    "anchore_image_detail",
    "anchore_remediation_handoff",
}


async def verify(wheel: str) -> None:
    clean_env = {key: value for key, value in os.environ.items() if not key.startswith("ANCHORE_")}
    transport = StdioTransport(command="uvx", args=["--from", wheel, "anchore-mcp"], env=clean_env)
    async with Client(transport) as client:
        tools = await client.list_tools()
    assert {tool.name for tool in tools} == EXPECTED


if __name__ == "__main__":
    asyncio.run(verify(sys.argv[1]))
```

Run: `uv run python scripts/smoke_wheel.py dist/anchore_mcp-4.0.0-py3-none-any.whl`

Expected: exit 0 without printing environment contents.

- [ ] **Step 7: Commit the breaking removal**

```bash
git add -A
git commit -S -m "chore!: remove Node and TypeScript implementation" -m "BREAKING CHANGE: anchore-mcp now runs as a Python 3.12 FastMCP stdio server through uv."
```

## Task 18: Final Verification and Release Readiness

**Files:**
- Modify only if verification finds a concrete defect

- [ ] **Step 1: Run the complete evidence set from a clean checkout**

Run: `uv sync --frozen --all-groups && uv run python scripts/check.py && uv run pytest -m performance tests/runtime/test_performance.py -q`

Expected: PASS with coverage at or above 90 percent.

- [ ] **Step 2: Verify repository and package identity**

Run:

```bash
uv run python -c "import anchore_mcp; assert anchore_mcp.__version__ == '4.0.0'"
git ls-files | rg '(package\.json|pnpm|\.ts$)'
git status --short
```

Expected: version assertion passes, Node search has no output, and working tree is clean.

- [ ] **Step 3: Review attack and leak evidence**

Confirm the final test report includes off-origin pagination, disabled redirects, expanded-body limits, account-aware one-entry cache, safe errors/logs, cancellation, repeated lifespan cleanup, and no surviving owned tasks. Do not declare completion if any evidence is missing.

- [ ] **Step 4: Create a final metadata commit only if verification required a fix**

```bash
git add pyproject.toml uv.lock src tests docs
git commit -S -m "chore: prepare 4.0.0 release"
```

Skip this commit when verification makes no changes.

---

## Execution Notes

- Use synthetic `.example`/`.invalid` hosts and `CVE-2099-*` values in all committed tests and docs.
- Keep FastMCP `RetryMiddleware`, response caching, background tasks, payload logging, and HTTP transport disabled.
- Keep stdout exclusive to MCP JSON-RPC; all diagnostics go through the bounded redacted stderr helper.
- Never cache by token. The single OpenAPI cache key includes base URL, API version, and account.
- Never interpret an untrusted pagination continuation as completion or no match.
- Run focused tests after every red/green step and create the listed signed micro-commit only when focused tests pass.
- Use the verification-before-completion skill before any completion claim or final release commit.
