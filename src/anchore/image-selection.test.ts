import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { clearOpenApiCacheForTests } from "./openapi-fetch.js";
import { selectImageForPolicyBlockingReport } from "./image-selection.js";

function testConn(): ResolvedAnchoreConnection {
  return {
    baseUrl: "https://anchore.example.com",
    username: "_api_key",
    password: "t",
    apiVersion: "v2",
  };
}

function okList(items: unknown[]): Response {
  return new Response(JSON.stringify({ items }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

const V1_REPOSITORY_UNAVAILABLE_MESSAGE =
  "Repository selection is unavailable for this v1 deployment because its OpenAPI does not advertise registry and repository filters on image tag summaries.";

function v1SummaryOpenApi(
  parameters: unknown[],
  path = "/v1/summaries/image-tags",
): unknown {
  return {
    paths: {
      [path]: {
        get: { parameters },
      },
    },
  };
}

beforeEach(() => {
  clearOpenApiCacheForTests();
});

describe("selectImageForPolicyBlockingReport", () => {
  it("uses a digest directly", async () => {
    const result = await selectImageForPolicyBlockingReport(
      { image_digest: "  sha256:direct  " },
      testConn(),
      { fetch: vi.fn() },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: { digest: "sha256:direct" },
    });
  });

  it("selects the newest analyzed digest for an exact reference", async () => {
    const requested = "docker.io/library/nginx:1.25";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:old",
          fulltag: requested,
          analyzed_at: "2026-04-01T00:00:00Z",
        },
        {
          image_digest: "sha256:new",
          fulltag: requested,
          analyzed_at: "2026-04-02T00:00:00Z",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: requested },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:new",
        reference: requested,
        repository: "docker.io/library/nginx",
        analysisTimestamp: "2026-04-02T00:00:00.000Z",
      },
    });
    expect(fetchMock.mock.calls[0][0]).toContain("full_tag=");
    expect(fetchMock.mock.calls[0][0]).not.toContain("fulltag=");
    expect(fetchMock.mock.calls[0][0]).toContain(encodeURIComponent(requested));
  });

  it("uses the v1 fulltag wire key for exact reference selection", async () => {
    const requested = "registry.example.com/team/app:1";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:v1",
          fulltag: requested,
          analyzed_at: "2026-04-02T00:00:00Z",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: requested },
      { ...testConn(), apiVersion: "v1" },
      { fetch: fetchMock },
    );

    expect(result.ok).toBe(true);
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain("/v1/images?fulltag=");
    expect(url).not.toContain("full_tag=");
  });

  it("fails closed when an exact digest-bearing reference row lacks a timestamp", async () => {
    const requested = "registry.example.com/team/app:1";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:older",
          full_tag: requested,
          analyzed_at: "2026-04-01T00:00:00Z",
        },
        {
          image_digest: "sha256:unknown-newness",
          full_tag: requested,
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: requested },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message:
        "Cannot prove newest image because a matching digest-bearing row lacked a reliable analysis timestamp.",
    });
  });

  it("ignores a matching digestless reference row with no timestamp", async () => {
    const requested = "registry.example.com/team/app:1";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:selectable",
          full_tag: requested,
          analyzed_at: "2026-04-01T00:00:00Z",
        },
        {
          full_tag: requested,
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: requested },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:selectable",
        reference: requested,
        repository: "registry.example.com/team/app",
        analysisTimestamp: "2026-04-01T00:00:00.000Z",
      },
    });
  });

  it("rejects a port-only colon reference without fetching", async () => {
    const fetchMock = vi.fn();
    const result = await selectImageForPolicyBlockingReport(
      { image_reference: "registry.example.com:5000/team/app" },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ignores rows with the same repository but a different tag for exact reference selection", async () => {
    const requested = "docker.io/library/nginx:1.25";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:requested",
          full_tag: requested,
          analyzedAt: "2026-04-02T00:00:00Z",
        },
        {
          image_digest: "sha256:other-tag",
          fulltag: "docker.io/library/nginx:latest",
          analyzedAt: "2026-04-03T00:00:00Z",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: requested },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:requested",
        reference: requested,
        repository: "docker.io/library/nginx",
        analysisTimestamp: "2026-04-02T00:00:00.000Z",
      },
    });
  });

  it("matches an exact reference from any row reference field", async () => {
    const requested = "docker.io/library/nginx:1.25";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:matched-later-field",
          fulltag: "docker.io/library/nginx:latest",
          imageTag: requested,
          analyzedAt: "2026-04-02T00:00:00Z",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: requested },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:matched-later-field",
        reference: requested,
        repository: "docker.io/library/nginx",
        analysisTimestamp: "2026-04-02T00:00:00.000Z",
      },
    });
  });

  it("does not synthesize an exact reference from conflicting repository aliases", async () => {
    const requested = "docker.io/library/nginx:1.25";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:wrong",
          image_detail: {
            registry: "docker.io",
            repo: "library/nginx",
            repository: "customer/private",
            tag: "1.25",
          },
          analyzed_at: "2026-04-02T00:00:00Z",
        },
      ]),
    );

    await expect(
      selectImageForPolicyBlockingReport(
        { image_reference: requested },
        testConn(),
        { fetch: fetchMock },
      ),
    ).resolves.toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message:
        "No matching image row had both a digest and a reliable analysis timestamp.",
    });
  });

  it("fails closed when exact-reference evidence exceeds safety limits", async () => {
    const requested = "docker.io/library/nginx:1.25";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:overflow",
          full_tag: requested,
          tags: Array.from(
            { length: 65 },
            (_, index) => `docker.io/library/nginx:extra-${index}`,
          ),
          analyzed_at: "2026-04-02T00:00:00Z",
        },
      ]),
    );

    await expect(
      selectImageForPolicyBlockingReport(
        { image_reference: requested },
        testConn(),
        { fetch: fetchMock },
      ),
    ).resolves.toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message: "Image reference evidence exceeded safety limits.",
    });
  });

  it("selects an exact coherent nested reference before checking timestamp trust", async () => {
    const requested = "docker.io/library/nginx:1.25";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:coherent",
          image_detail: {
            registry: "docker.io",
            repository: "library/nginx",
            tag: "1.25",
          },
          analyzed_at: "2026-04-02T00:00:00Z",
        },
      ]),
    );

    await expect(
      selectImageForPolicyBlockingReport(
        { image_reference: requested },
        testConn(),
        { fetch: fetchMock },
      ),
    ).resolves.toMatchObject({
      ok: true,
      selectedImage: {
        digest: "sha256:coherent",
        reference: requested,
        analysisTimestamp: "2026-04-02T00:00:00.000Z",
      },
    });
  });

  it("selects the newest exact registry and repository pair across tags", async () => {
    const registry = "registry.example.com";
    const repository = "team/app";
    const qualifiedRepository = `${registry}/${repository}`;
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:old",
          full_tag: `${qualifiedRepository}:1.0`,
          analyzed_at: 1_775_001_600,
        },
        {
          image_digest: "sha256:new",
          full_tag: `${qualifiedRepository}:2.0`,
          analyzed_at: 1_775_174_400_000,
        },
        {
          image_digest: "sha256:wrong-registry",
          full_tag: `other.example.com/${repository}:9.0`,
          analyzed_at: 1_775_260_800_000,
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_registry: registry, image_repository: repository },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:new",
        reference: "registry.example.com/team/app:2.0",
        repository: qualifiedRepository,
        analysisTimestamp: "2026-04-03T00:00:00.000Z",
      },
    });
    const requestUrl = fetchMock.mock.calls[0][0] as string;
    expect(requestUrl).toContain("/v2/summaries/image-tags?");
    expect(requestUrl).not.toContain("/v2/images?");
    expect(requestUrl).toContain("registry=registry.example.com");
    expect(requestUrl).toContain("repository=team%2Fapp");
    expect(requestUrl).toContain("analysis_status=analyzed");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(requestUrl).not.toContain("/openapi.json");
  });

  it.each([
    ["route missing", { paths: {} }],
    [
      "GET missing",
      {
        paths: {
          "/v1/summaries/image-tags": {
            post: {
              parameters: [
                { name: "registry", in: "query" },
                { name: "repository", in: "query" },
              ],
            },
          },
        },
      },
    ],
    [
      "repository parameter missing",
      v1SummaryOpenApi([{ name: "registry", in: "query" }]),
    ],
    [
      "unresolved parameter refs",
      v1SummaryOpenApi([
        { $ref: "#/components/parameters/registry" },
        { $ref: "#/components/parameters/repository" },
      ]),
    ],
  ])("fails closed for v1 when OpenAPI support is %s", async (_case, doc) => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(doc), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      { ...testConn(), apiVersion: "v1" },
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message: V1_REPOSITORY_UNAVAILABLE_MESSAGE,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).toContain("/v1/openapi.json");
    expect(String(fetchMock.mock.calls[0][0])).not.toContain("/summaries/image-tags");
  });

  it("returns the static v1 unavailable error when OpenAPI fetch fails", async () => {
    const rawMarker = "RAW_OPENAPI_ERROR_MARKER";
    const fetchMock = vi.fn().mockRejectedValue(new Error(rawMarker));

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      { ...testConn(), apiVersion: "v1" },
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message: V1_REPOSITORY_UNAVAILABLE_MESSAGE,
    });
    expect(JSON.stringify(result)).not.toContain(rawMarker);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).toContain("/v1/openapi.json");
  });

  it("fails v1 repository selection without following an OpenAPI redirect", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("", {
        status: 302,
        headers: { Location: "https://evil.example/openapi.json" },
      }),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      { ...testConn(), apiVersion: "v1" },
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message: V1_REPOSITORY_UNAVAILABLE_MESSAGE,
    });
    expect(JSON.stringify(result)).not.toContain("evil.example");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ redirect: "manual" });
  });

  it.each([
    "/v1/summaries/image-tags",
    "/summaries/image-tags",
  ])("proceeds with v1 repository selection when OpenAPI advertises %s", async (path) => {
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/v1/openapi.json")) {
        return Promise.resolve(
          new Response(
            JSON.stringify(
              v1SummaryOpenApi(
                [
                  { name: "registry", in: "query" },
                  { name: "repository", in: "query" },
                ],
                path,
              ),
            ),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ),
        );
      }
      return Promise.resolve(
        okList([
          {
            image_digest: "sha256:v1-selected",
            full_tag: "registry.example.com/team/app:1",
            analyzed_at: "2026-04-03T00:00:00Z",
          },
        ]),
      );
    });

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      { ...testConn(), apiVersion: "v1" },
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({
      ok: true,
      selectedImage: { digest: "sha256:v1-selected" },
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[0][0])).toContain("/v1/openapi.json");
    expect(String(fetchMock.mock.calls[1][0])).toContain(
      "/v1/summaries/image-tags?",
    );
  });

  it("fails closed when an exact repository digest row has an invalid timestamp", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:older",
          full_tag: "registry.example.com/team/app:1",
          analyzed_at: "2026-04-01T00:00:00Z",
        },
        {
          image_digest: "sha256:unknown-newness",
          full_tag: "registry.example.com/team/app:2",
          analyzed_at: "not-a-timestamp",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message:
        "Cannot prove newest image because a matching digest-bearing row lacked a reliable analysis timestamp.",
    });
  });

  it("ignores a matching digestless repository row with an invalid timestamp", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:selectable",
          full_tag: "registry.example.com/team/app:1",
          analyzed_at: "2026-04-01T00:00:00Z",
        },
        {
          full_tag: "registry.example.com/team/app:2",
          analyzed_at: "not-a-timestamp",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:selectable",
        reference: "registry.example.com/team/app:1",
        repository: "registry.example.com/team/app",
        analysisTimestamp: "2026-04-01T00:00:00.000Z",
      },
    });
  });

  it("continues image-tag summary pages while total_rows reports more rows", async () => {
    const registry = "registry.example.com";
    const repository = "team/app";
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      const page = new URL(url).searchParams.get("page");
      if (page === "1") {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              items: [
                {
                  image_digest: "sha256:old",
                  full_tag: `${registry}/${repository}:1`,
                  analyzed_at: "2026-04-01T00:00:00Z",
                },
              ],
              total_rows: 2,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ),
        );
      }
      return Promise.resolve(
        new Response(
          JSON.stringify({
            items: [
              {
                image_digest: "sha256:new",
                full_tag: `${registry}/${repository}:2`,
                analyzed_at: "2026-04-03T00:00:00Z",
              },
            ],
            total_rows: 2,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    });

    const result = await selectImageForPolicyBlockingReport(
      { image_registry: registry, image_repository: repository },
      testConn(),
      { fetch: fetchMock },
    );

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result).toMatchObject({
      ok: true,
      selectedImage: { digest: "sha256:new" },
    });
  });

  it("treats summary full_tag as authoritative when aliases conflict", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:conflict",
          full_tag: "other.example.com/team/app:latest",
          image_tag: "registry.example.com/team/app:latest",
          analyzed_at: "2026-04-03T00:00:00Z",
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
    });
  });

  it("returns a provenance-safe selector error when summary caps prevent completion", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [
            {
              image_digest: "sha256:first",
              full_tag: "registry.example.com/team/app:1",
              analyzed_at: "2026-04-01T00:00:00Z",
            },
          ],
          total_rows: 2,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock, listCaps: { maxPages: 1, maxItems: 1 } },
    );

    expect(result).toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message: "Stopped after collecting 1 image tag summary row(s) (maxItems cap).",
    });
  });

  it("uses official full_tag when alternate nested fields are also present", async () => {
    const registry = "registry.example.com";
    const repository = "team/app";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          imageDigest: "sha256:matched-later-repo-field",
          full_tag: "registry.example.com/team/app:2.0",
          analyzed_at: "2026-04-03T00:00:00Z",
          imageDetails: [
            {
              imageRegistry: registry,
              imageRepository: repository,
              image_tag: "registry.example.com/team/app:2.0",
            },
          ],
        },
        {
          imageDigest: "sha256:matched-derived-reference",
          full_tag: "registry.example.com/team/app:3.0",
          analyzed_at: "2026-04-04T00:00:00Z",
          imageDetails: [
            {
              registry,
              repository: "team/wrong",
              fulltag: "registry.example.com/team/wrong:latest",
              imageTag: "registry.example.com/team/app:3.0",
            },
          ],
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_registry: registry, image_repository: repository },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:matched-derived-reference",
        reference: "registry.example.com/team/app:3.0",
        repository: "registry.example.com/team/app",
        analysisTimestamp: "2026-04-04T00:00:00.000Z",
      },
    });
  });

  it("does not synthesize a match from conflicting registry and repository aliases", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:synthetic-only",
          analyzed_at: "2026-04-05T00:00:00Z",
          image_detail: [
            {
              registry: "registry.example.com",
              imageRegistry: "other.example.com",
              repository: "other/team",
              imageRepository: "team/app",
              tag: "5.0",
            },
          ],
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({ ok: false, status: "image_selection_error" });
  });

  it("selects summary rows with official full_tag alongside nested metadata", async () => {
    const registry = "containers.example.com";
    const repository = "psf/help-site";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:old",
          full_tag: "containers.example.com/psf/help-site:3",
          analyzed_at: "2026-04-23T00:00:00Z",
          image_detail: [
            {
              registry,
              repo: repository,
              tag: "3",
              full_tag: "containers.example.com/psf/help-site:3",
            },
          ],
        },
        {
          image_digest: "sha256:new",
          full_tag: "containers.example.com/psf/help-site:4",
          analyzed_at: "2026-04-24T00:00:00Z",
          image_detail: [
            {
              registry,
              repo: repository,
              tag: "4",
              full_tag: "containers.example.com/psf/help-site:4",
            },
          ],
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_registry: registry, image_repository: repository },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:new",
        reference: "containers.example.com/psf/help-site:4",
        repository: "containers.example.com/psf/help-site",
        analysisTimestamp: "2026-04-24T00:00:00.000Z",
      },
    });
  });

  it("matches exact references from nested v2 image_detail rows", async () => {
    const requested = "containers.example.com/psf/help-site:4";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:nested-reference",
          analyzed_at: "2026-04-24T00:00:00Z",
          image_detail: [
            {
              registry: "containers.example.com",
              repo: "psf/help-site",
              tag: "4",
              full_tag: requested,
            },
          ],
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: requested },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: true,
      selectedImage: {
        digest: "sha256:nested-reference",
        reference: requested,
        repository: "containers.example.com/psf/help-site",
        analysisTimestamp: "2026-04-24T00:00:00.000Z",
      },
    });
  });

  it("returns image_selection_error when the newest timestamp is tied across digests", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:a",
          full_tag: "registry.example.com/team/app:1.0",
          analyzed_at: "2026-04-02T00:00:00Z",
          image_detail: [
            { registry: "registry.example.com", repo: "team/app", tag: "1.0" },
          ],
        },
        {
          image_digest: "sha256:b",
          full_tag: "registry.example.com/team/app:2.0",
          analyzed_at: "2026-04-02T00:00:00Z",
          image_detail: [
            { registry: "registry.example.com", repo: "team/app", tag: "2.0" },
          ],
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message:
        "Newest analyzed image is ambiguous: 2 digests share timestamp 2026-04-02T00:00:00.000Z.",
    });
  });

  it("canonicalizes string timestamps before selector-safe interpolation", async () => {
    const rawTimestamp =
      "Thu, 02 Apr 2026 00:00:00 GMT (CUSTOMER_SECRET_MARKER)";
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:a",
          full_tag: "registry.example.com/team/app:1",
          analyzed_at: rawTimestamp,
        },
        {
          image_digest: "sha256:b",
          full_tag: "registry.example.com/team/app:2",
          analyzed_at: rawTimestamp,
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({
      ok: false,
      messageSource: "selector",
      message:
        "Newest analyzed image is ambiguous: 2 digests share timestamp 2026-04-02T00:00:00.000Z.",
    });
    expect(JSON.stringify(result)).not.toContain("CUSTOMER_SECRET_MARKER");
  });

  it("marks a list-images exception as an untrusted backend message", async () => {
    const backendMessage =
      "Newest analyzed image is ambiguous: 2 digests share timestamp AKIAEXAMPLESECRET1234.";
    const fetchMock = vi.fn().mockRejectedValue(new Error(backendMessage));

    const result = await selectImageForPolicyBlockingReport(
      { image_reference: "docker.io/library/nginx:latest" },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "backend",
      message: backendMessage,
    });
  });

  it("returns image_selection_error when no matching row has a valid timestamp", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:a",
          full_tag: "registry.example.com/team/app:1.0",
          analyzed_at: "not-a-date",
          image_detail: [
            { registry: "registry.example.com", repo: "team/app", tag: "1.0" },
          ],
        },
        {
          image_digest: "sha256:b",
          full_tag: "registry.example.com/team/app:2.0",
          image_detail: [
            { registry: "registry.example.com", repo: "team/app", tag: "2.0" },
          ],
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({
      ok: false,
      status: "image_selection_error",
    });
  });

  it("fails closed on an out-of-range numeric analysis timestamp", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:invalid-time",
          full_tag: "registry.example.com/team/app:bad",
          analyzed_at: Number.MAX_VALUE,
        },
        {
          image_digest: "sha256:valid-time",
          full_tag: "registry.example.com/team/app:good",
          analyzed_at: 1_775_174_400,
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message:
        "Cannot prove newest image because a matching digest-bearing row lacked a reliable analysis timestamp.",
    });
  });

  it("supports epoch milliseconds before 2001 without treating them as seconds", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      okList([
        {
          image_digest: "sha256:iso-old",
          full_tag: "registry.example.com/team/app:old",
          analyzed_at: "1999-01-01T00:00:00Z",
        },
        {
          image_digest: "sha256:millis-new",
          full_tag: "registry.example.com/team/app:new",
          analyzed_at: 946_684_800_000,
        },
      ]),
    );

    const result = await selectImageForPolicyBlockingReport(
      {
        image_registry: "registry.example.com",
        image_repository: "team/app",
      },
      testConn(),
      { fetch: fetchMock },
    );

    expect(result).toMatchObject({
      ok: true,
      selectedImage: {
        digest: "sha256:millis-new",
        analysisTimestamp: "2000-01-01T00:00:00.000Z",
      },
    });
  });

  it("requires exactly one locator", async () => {
    const connection = testConn();
    const fetchMock = vi.fn();

    await expect(
      selectImageForPolicyBlockingReport({}, connection, { fetch: fetchMock }),
    ).resolves.toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message:
        "Supply exactly one of image_digest, image_reference, or the image_registry and image_repository pair.",
    });
    await expect(
      selectImageForPolicyBlockingReport(
        {
          image_digest: "sha256:a",
          image_reference: "docker.io/library/nginx:latest",
        },
        connection,
        { fetch: fetchMock },
      ),
    ).resolves.toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message:
        "Supply exactly one of image_digest, image_reference, or the image_registry and image_repository pair.",
    });
    await expect(
      selectImageForPolicyBlockingReport(
        {
          image_digest: "sha256:a",
          image_registry: "registry.example.com",
          image_repository: "team/app",
        },
        connection,
        { fetch: fetchMock },
      ),
    ).resolves.toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message:
        "Supply exactly one of image_digest, image_reference, or the image_registry and image_repository pair.",
    });
    await expect(
      selectImageForPolicyBlockingReport(
        {
          image_reference: "docker.io/library/nginx:latest",
          image_registry: "registry.example.com",
          image_repository: "team/app",
        },
        connection,
        { fetch: fetchMock },
      ),
    ).resolves.toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message:
        "Supply exactly one of image_digest, image_reference, or the image_registry and image_repository pair.",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects incomplete registry and repository component pairs", async () => {
    const connection = testConn();
    const fetchMock = vi.fn();

    await expect(
      selectImageForPolicyBlockingReport(
        { image_registry: "registry.example.com" },
        connection,
        { fetch: fetchMock },
      ),
    ).resolves.toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message: "Supply image_registry and image_repository together.",
    });
    await expect(
      selectImageForPolicyBlockingReport(
        { image_repository: "team/app" },
        connection,
        { fetch: fetchMock },
      ),
    ).resolves.toEqual({
      ok: false,
      status: "image_selection_error",
      messageSource: "selector",
      message: "Supply image_registry and image_repository together.",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    { image_registry: "", image_repository: "team/app" },
    { image_registry: "registry.example.com", image_repository: "" },
    { image_registry: `${"r".repeat(1025)}`, image_repository: "team/app" },
    { image_registry: "registry.example.com", image_repository: "r".repeat(1025) },
    { image_registry: "registry.example.com\n", image_repository: "team/app" },
    { image_registry: "registry.example.com", image_repository: "team\u0000/app" },
    { image_registry: "registry.example.com/path", image_repository: "team/app" },
    { image_registry: "registry.example.com", image_repository: "/team/app" },
    { image_registry: "registry.example.com", image_repository: "team/app/" },
    { image_registry: "registry.example.com", image_repository: "team/app:latest" },
  ])("rejects an invalid registry or repository component: %o", async (locator) => {
    const fetchMock = vi.fn();
    const result = await selectImageForPolicyBlockingReport(locator, testConn(), {
      fetch: fetchMock,
    });

    expect(result).toMatchObject({ ok: false, status: "image_selection_error" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
