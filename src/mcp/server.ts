import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import {
  getConnectionSnapshot,
  loadConnectionFromEnv,
} from "../config/connection.js";
import { runListImages } from "../tools/images.js";
import { runPolicyBlockingVulnerabilities } from "../tools/policy-blocking-vulnerabilities.js";
import { runRemediationHandoff } from "../tools/remediation-handoff.js";
import { runImageDetail, runImagePolicyCheck } from "../tools/reports.js";
import { runImageSbom } from "../tools/sbom.js";
import { runImageVulnerabilities } from "../tools/vulnerabilities.js";

const SERVER_NAME = "anchore-mcp";
const SERVER_VERSION = "0.1.0";

/** Non-secret connection info for tools (R8 context). Exported for tests. */
export function getConnectionInfo(connection: ResolvedAnchoreConnection) {
  return getConnectionSnapshot(connection);
}

export type CreateMcpServerOptions = {
  /**
   * Tests: use a fixed connection. Production omits this so env is read when each tool runs
   * (stdio handshake and trust checks can run without ANCHORE_* set).
   */
  connection?: ResolvedAnchoreConnection;
};

export function createMcpServer(options: CreateMcpServerOptions = {}): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  server.tool(
    "anchore_connection_info",
    "Show the Anchore base URL and optional account for this MCP server (non-secret). One MCP process connects to one Anchore; add another MCP entry for another deployment.",
    async () => {
      try {
        const c = options.connection ?? loadConnectionFromEnv();
        const text = JSON.stringify(getConnectionInfo(c), null, 2);
        return {
          content: [{ type: "text", text }],
        };
      } catch (e) {
        const text = JSON.stringify(
          {
            configured: false,
            message:
              "Anchore is not configured yet. Set ANCHORE_URL and ANCHORE_TOKEN in this MCP server's environment (see README). Trust checks may run the server without those variables.",
            detail: e instanceof Error ? e.message : String(e),
          },
          null,
          2,
        );
        return {
          content: [{ type: "text", text }],
        };
      }
    },
  );

  server.tool(
    "anchore_list_images",
    "List analyzed images (default GET /v2/images; set ANCHORE_API_VERSION=v1 for legacy /v1/images). The MCP merges paginated responses client-side; if the catalog is larger than internal caps, the JSON includes listEnumerationIncomplete. Optional query filters depend on your Anchore build — see your deployment /v2/openapi.json.",
    {
      fulltag: z
        .string()
        .optional()
        .describe("When supported, filter by full image tag"),
      vulnerability_id: z
        .string()
        .optional()
        .describe("When supported, filter by CVE id (e.g. CVE-2024-1234)"),
      list_query: z
        .record(z.string(), z.string())
        .optional()
        .describe(
          "Extra GET /v1|/v2/images query params (keys must match deployment OpenAPI or MCP fallback allowlist).",
        ),
    },
    async (args) => runListImages(args, { connection: options.connection }),
  );

  server.tool(
    "anchore_image_vulnerabilities",
    "List vulnerabilities for an image (default GET /v2/images/{digest}/vuln/all; v1 uses .../vulnerabilities). Pass exactly one of image_digest or image_reference (fully qualified registry/repo:tag to resolve in the MCP). Set ANCHORE_API_VERSION if needed.",
    {
      image_digest: z.string().optional().describe("Image digest, e.g. sha256:…"),
      image_reference: z
        .string()
        .optional()
        .describe("Fully qualified image reference (registry/repo:tag); MCP resolves via list+fulltag."),
    },
    async (args) =>
      runImageVulnerabilities(args, { connection: options.connection }),
  );

  server.tool(
    "anchore_image_sbom",
    "Fetch SBOM JSON for an analyzed image. Anchore routes are digest-keyed (GET /v2/images/{digest}/sboms/...). Pass exactly one of image_digest or image_reference (FQDN registry/repo:tag); the MCP resolves references before the SBOM GET. Responses include sizeBytes (R15). Default max_response_bytes=20MB — increase explicitly for huge SBOMs; otherwise the tool fails with a clear error (no silent truncation). Confirm paths on your deployment /v2/openapi.json.",
    {
      image_digest: z.string().optional().describe("Image digest, e.g. sha256:…"),
      image_reference: z
        .string()
        .optional()
        .describe("Fully qualified image reference; MCP resolves to digest before SBOM GET."),
      format: z
        .enum(["normal", "spdx", "cyclonedx"])
        .describe(
          "normal = Syft native JSON; spdx / cyclonedx = interchange JSON variants",
        ),
      max_response_bytes: z
        .number()
        .int()
        .positive()
        .max(100_000_000)
        .optional()
        .describe(
          "Reject larger HTTP bodies (UTF-8 bytes). Default 20_000_000.",
        ),
    },
    async (args) => runImageSbom(args, { connection: options.connection }),
  );

  server.tool(
    "anchore_image_policy_check",
    "Policy compliance evaluation (GET /v2/images/{digest}/check). Pass exactly one of image_digest or image_reference for the path digest. Optional tag is only for Anchore /check query context — not a substitute for the path digest and not auto-filled from image_reference.",
    {
      image_digest: z.string().optional().describe("Image digest for the policy path, e.g. sha256:…"),
      image_reference: z
        .string()
        .optional()
        .describe("FQDN registry/repo:tag; MCP resolves to digest for the path."),
      tag: z
        .string()
        .optional()
        .describe(
          "Full image tag for /check query if your Anchore version requires it (separate from image_reference).",
        ),
      base_digest: z
        .string()
        .optional()
        .describe("Optional base image digest for comparison checks"),
    },
    async (args) =>
      runImagePolicyCheck(args, { connection: options.connection }),
  );

  server.tool(
    "anchore_policy_blocking_vulnerabilities",
    "Return only vulnerability remediations proven to change an image policy from red to green. Pass exactly one locator mode: image_digest, image_reference, or image_registry + image_repository. When a reference is resolved or selected, it is used as Anchore /check tag context unless tag is supplied explicitly.",
    {
      image_digest: z.string().optional().describe("Digest locator."),
      image_reference: z
        .string()
        .optional()
        .describe(
          "Fully qualified registry/repo:tag; newest analyzed matching digest selected.",
        ),
      image_registry: z
        .string()
        .optional()
        .describe(
          "Anchore registry component; requires image_repository.",
        ),
      image_repository: z
        .string()
        .optional()
        .describe(
          "Anchore repository component without registry or tag; requires image_registry.",
        ),
      tag: z
        .string()
        .optional()
        .describe(
          "Anchore /check query context. Defaults to the selected image reference when available.",
        ),
      base_digest: z
        .string()
        .optional()
        .describe("Anchore /check comparison context only."),
    },
    async (args) =>
      runPolicyBlockingVulnerabilities(args, {
        connection: options.connection,
      }),
  );

  server.tool(
    "anchore_image_detail",
    "Single image analysis record (GET /v2/images/{digest}). Pass exactly one of image_digest or image_reference (FQDN); the MCP resolves references to a digest. Includes sizeBytes for the JSON payload (R15).",
    {
      image_digest: z.string().optional().describe("Image digest, e.g. sha256:…"),
      image_reference: z
        .string()
        .optional()
        .describe("Fully qualified image reference; MCP resolves to digest."),
    },
    async (args) => runImageDetail(args, { connection: options.connection }),
  );

  server.tool(
    "anchore_remediation_handoff",
    "Build a versioned remediation handoff bundle (R7): image detail + vulnerabilities + optional policy check. Pass exactly one of image_digest or image_reference (FQDN). Optional tag is only for the policy /check call when required — not auto-filled from image_reference. See docs/remediation-handoff-schema.md. R8 context + R15 total sizeBytes.",
    {
      image_digest: z.string().optional().describe("Image digest, e.g. sha256:…"),
      image_reference: z
        .string()
        .optional()
        .describe("Fully qualified image reference; MCP resolves to digest."),
      tag: z
        .string()
        .optional()
        .describe(
          "Full image tag for policy check when your Anchore version requires it (orthogonal to image_reference).",
        ),
      base_digest: z
        .string()
        .optional()
        .describe("Optional base image digest for policy comparison"),
      include_policy_check: z
        .boolean()
        .optional()
        .describe(
          "When false, skip GET .../check (omit policy evidence). Default true.",
        ),
    },
    async (args) =>
      runRemediationHandoff(args, { connection: options.connection }),
  );

  return server;
}

/**
 * Stdio MCP: the host must keep stdin open for the lifetime of the session.
 * See README “MCP stdin / trust race”. Avoid extra stderr noise here — some hosts treat
 * any stderr as a failed MCP child and can leave agent/MCP UI stuck until restart.
 */
export async function main(): Promise<void> {
  process.stdin.resume();

  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
