import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { AnchoreApiVersion } from "../anchore/api-paths.js";
import {
  imageByDigestPath,
  imagePolicyCheckPath,
  imageVulnerabilitiesPath,
} from "../anchore/api-paths.js";
import { createAnchoreClient } from "../anchore/client.js";
import { loadConnectionFromEnv } from "../config/connection.js";
import { logStderrLine } from "../logging/safe-log.js";
import type { AnchoreToolRunOptions } from "./anchore-run-options.js";
import { anchoreFailureMessage } from "./anchore-tool-error.js";
import type { ToolContextFields } from "./context.js";
import { formatAnchoreToolJson } from "./format.js";
import { resolveDigestForAnchorePath } from "./image-input.js";

/** Documented in `docs/remediation-handoff-schema.md`; bump together with schema. */
export const REMEDIATION_HANDOFF_VERSION = "1.0.0" as const;

export type RemediationHandoffDeployment = {
  baseUrl: string;
  account?: string;
  apiVersion: AnchoreApiVersion;
};

export type RemediationHandoffEvidence = {
  imageDetail: unknown;
  imageDetailSizeBytes: number;
  vulnerabilities: unknown;
  vulnerabilitiesSizeBytes: number;
  policyCheck?: unknown;
  policyCheckSizeBytes?: number;
};

/** Inner bundle (becomes `anchore` in `AnchoreToolPayload` from `formatAnchoreToolJson`). */
export type RemediationHandoffPayload = {
  handoffVersion: typeof REMEDIATION_HANDOFF_VERSION;
  generatedAt: string;
  deployment: RemediationHandoffDeployment;
  imageDigest: string;
  evidence: RemediationHandoffEvidence;
};

function countVulnerabilityRecords(data: unknown): number | null {
  if (data !== null && typeof data === "object") {
    if (
      "vulnerabilities" in data &&
      Array.isArray((data as { vulnerabilities: unknown }).vulnerabilities)
    ) {
      return (data as { vulnerabilities: unknown[] }).vulnerabilities.length;
    }
    if ("items" in data && Array.isArray((data as { items: unknown }).items)) {
      return (data as { items: unknown[] }).items.length;
    }
  }
  if (Array.isArray(data)) {
    return data.length;
  }
  return null;
}

function summarizeRemediationHandoff(
  digest: string,
  vulnData: unknown,
  includePolicy: boolean,
  hasPolicy: boolean,
): string {
  const n = countVulnerabilityRecords(vulnData);
  const vulnPhrase =
    n === null
      ? "vulnerability evidence"
      : n === 0
        ? "no vulnerability records"
        : `${n} vulnerability record(s)`;
  if (includePolicy && hasPolicy) {
    return `Remediation handoff for ${digest}: image detail, ${vulnPhrase}, and policy check (Anchore API evidence).`;
  }
  return `Remediation handoff for ${digest}: image detail and ${vulnPhrase} (Anchore API evidence).`;
}

export type RemediationHandoffArgs = {
  image_digest?: string;
  image_reference?: string;
  tag?: string;
  base_digest?: string;
  /** When false, skip GET .../check (bundle has no policy fields). Default true. */
  include_policy_check?: boolean;
};

/**
 * R7 — Composite read-only evidence: image detail + vulnerabilities (+ optional policy).
 * Consumers add repo/org routing; no source-repo fields required.
 */
export async function runRemediationHandoff(
  args: RemediationHandoffArgs,
  options?: AnchoreToolRunOptions,
): Promise<CallToolResult> {
  const includePolicy = args.include_policy_check !== false;

  let connection;
  try {
    connection = options?.connection ?? loadConnectionFromEnv();
  } catch (err) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              error: true,
              message:
                err instanceof Error
                  ? err.message
                  : "Anchore connection is not configured.",
            },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }

  const resolved = await resolveDigestForAnchorePath(
    args,
    connection,
    options,
    "remediation handoff",
  );
  if (!resolved.ok) {
    return resolved.result;
  }
  const { digest, resolvedFromImageReference } = resolved;

  try {
    const client = createAnchoreClient(connection, { fetch: options?.fetch });
    const detailPath = imageByDigestPath(connection.apiVersion, digest);
    const vulnPath = imageVulnerabilitiesPath(connection.apiVersion, digest);

    const [detailRes, vulnRes] = await Promise.all([
      client.getJsonWithByteLength<unknown>(detailPath),
      client.getJsonWithByteLength<unknown>(vulnPath),
    ]);

    let policyRes: { data: unknown; byteLength: number } | undefined;
    if (includePolicy) {
      const query = new URLSearchParams();
      if (args.tag?.trim()) {
        query.set("tag", args.tag.trim());
      }
      if (args.base_digest?.trim()) {
        query.set("base_digest", args.base_digest.trim());
      }
      const policyPath = imagePolicyCheckPath(
        connection.apiVersion,
        digest,
        query,
      );
      policyRes = await client.getJsonWithByteLength<unknown>(policyPath);
    }

    const evidence: RemediationHandoffEvidence = {
      imageDetail: detailRes.data,
      imageDetailSizeBytes: detailRes.byteLength,
      vulnerabilities: vulnRes.data,
      vulnerabilitiesSizeBytes: vulnRes.byteLength,
      ...(policyRes !== undefined
        ? {
            policyCheck: policyRes.data,
            policyCheckSizeBytes: policyRes.byteLength,
          }
        : {}),
    };

    const payload: RemediationHandoffPayload = {
      handoffVersion: REMEDIATION_HANDOFF_VERSION,
      generatedAt: new Date().toISOString(),
      deployment: {
        baseUrl: connection.baseUrl,
        apiVersion: connection.apiVersion,
        ...(connection.account !== undefined
          ? { account: connection.account }
          : {}),
      },
      imageDigest: digest,
      evidence,
    };

    const ctx: ToolContextFields = {
      baseUrl: connection.baseUrl,
      account: connection.account,
      apiVersion: connection.apiVersion,
      action: "remediation handoff",
      ...(resolvedFromImageReference !== undefined
        ? { resolvedFromImageReference }
        : {}),
    };
    const summaryLine = summarizeRemediationHandoff(
      digest,
      vulnRes.data,
      includePolicy,
      policyRes !== undefined,
    );
    const totalBytes =
      detailRes.byteLength +
      vulnRes.byteLength +
      (policyRes?.byteLength ?? 0);
    const text = formatAnchoreToolJson(ctx, summaryLine, payload, {
      sizeBytes: totalBytes,
    });
    return { content: [{ type: "text", text }] };
  } catch (err) {
    logStderrLine(`anchore_remediation_handoff: ${anchoreFailureMessage(err)}`);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { error: true, message: anchoreFailureMessage(err) },
            null,
            2,
          ),
        },
      ],
      isError: true,
    };
  }
}
