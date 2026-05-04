import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  imagePolicyCheckPath,
  imageVulnerabilitiesPath,
} from "../anchore/api-paths.js";
import { createAnchoreClient } from "../anchore/client.js";
import {
  selectImageForPolicyBlockingReport,
  type PolicyBlockingImageLocator,
  type SelectedImage,
} from "../anchore/image-selection.js";
import {
  extractPolicyBlockingFindings,
  policyStatusFromPayload,
} from "../anchore/policy-blocker-extract.js";
import {
  buildBlockingVulnerabilities,
  extractVulnerabilityRecords,
  type BlockingVulnerability,
} from "../anchore/vulnerability-records.js";
import { loadConnectionFromEnv } from "../config/connection.js";
import { logStderrLine } from "../logging/safe-log.js";
import type { AnchoreToolRunOptions } from "./anchore-run-options.js";
import { anchoreFailureMessage } from "./anchore-tool-error.js";
import type { ToolContextFields } from "./context.js";
import { formatAnchoreToolJson } from "./format.js";

export const POLICY_BLOCKING_VULNS_REPORT_VERSION = "1.0.0" as const;

export type PolicyBlockingVulnerabilitiesArgs = PolicyBlockingImageLocator & {
  tag?: string;
  base_digest?: string;
};

export type PolicyBlockingVulnerabilitiesPayload = {
  reportVersion: typeof POLICY_BLOCKING_VULNS_REPORT_VERSION;
  policyRemediationStatus: "already_green" | "blocking_vulnerabilities_found";
  selectedImage: SelectedImage;
  blockingVulnerabilities: BlockingVulnerability[];
};

function errorResult(payload: Record<string, unknown>): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    isError: true,
  };
}

function connectionErrorMessage(err: unknown): string {
  return err instanceof Error
    ? err.message
    : "Anchore connection is not configured.";
}

function policyQuery(args: PolicyBlockingVulnerabilitiesArgs): URLSearchParams {
  const query = new URLSearchParams();
  if (args.tag?.trim()) {
    query.set("tag", args.tag.trim());
  }
  if (args.base_digest?.trim()) {
    query.set("base_digest", args.base_digest.trim());
  }
  return query;
}

function summaryLine(payload: PolicyBlockingVulnerabilitiesPayload): string {
  if (payload.policyRemediationStatus === "already_green") {
    return `Policy check is already green for ${payload.selectedImage.digest}; no blocking vulnerability remediation is needed.`;
  }

  return `Found ${payload.blockingVulnerabilities.length} policy-blocking vulnerability record(s) for ${payload.selectedImage.digest}.`;
}

/**
 * Focused remediation runner: prove which vulnerability records are blocking policy.
 */
export async function runPolicyBlockingVulnerabilities(
  args: PolicyBlockingVulnerabilitiesArgs,
  options?: AnchoreToolRunOptions,
): Promise<CallToolResult> {
  let connection;
  try {
    connection = options?.connection ?? loadConnectionFromEnv();
  } catch (err) {
    return errorResult({
      error: true,
      message: connectionErrorMessage(err),
      policyRemediationStatus: "image_selection_error",
    });
  }

  const selected = await selectImageForPolicyBlockingReport(args, connection, {
    fetch: options?.fetch,
  });
  if (!selected.ok) {
    return errorResult({
      error: true,
      message: selected.message,
      policyRemediationStatus: selected.status,
    });
  }

  const ctx: ToolContextFields = {
    baseUrl: connection.baseUrl,
    account: connection.account,
    apiVersion: connection.apiVersion,
    action: "policy blocking vulnerabilities",
  };

  try {
    const client = createAnchoreClient(connection, { fetch: options?.fetch });
    const policyData = await client.getJson<unknown>(
      imagePolicyCheckPath(
        connection.apiVersion,
        selected.selectedImage.digest,
        policyQuery(args),
      ),
    );

    if (policyStatusFromPayload(policyData) === "green") {
      const payload: PolicyBlockingVulnerabilitiesPayload = {
        reportVersion: POLICY_BLOCKING_VULNS_REPORT_VERSION,
        policyRemediationStatus: "already_green",
        selectedImage: selected.selectedImage,
        blockingVulnerabilities: [],
      };
      return {
        content: [
          {
            type: "text",
            text: formatAnchoreToolJson(ctx, summaryLine(payload), payload),
          },
        ],
      };
    }

    const vulnerabilityData = await client.getJson<unknown>(
      imageVulnerabilitiesPath(
        connection.apiVersion,
        selected.selectedImage.digest,
      ),
    );
    const blockingVulnerabilities = buildBlockingVulnerabilities(
      extractPolicyBlockingFindings(policyData),
      extractVulnerabilityRecords(vulnerabilityData),
    );

    if (blockingVulnerabilities.length === 0) {
      return errorResult({
        error: true,
        message:
          "Policy is non-green, but no exact blocking vulnerability remediation could be proven from policy and vulnerability evidence.",
        policyRemediationStatus: "red_policy_without_proven_vulnerability_fix",
      });
    }

    const payload: PolicyBlockingVulnerabilitiesPayload = {
      reportVersion: POLICY_BLOCKING_VULNS_REPORT_VERSION,
      policyRemediationStatus: "blocking_vulnerabilities_found",
      selectedImage: selected.selectedImage,
      blockingVulnerabilities,
    };
    return {
      content: [
        {
          type: "text",
          text: formatAnchoreToolJson(ctx, summaryLine(payload), payload),
        },
      ],
    };
  } catch (err) {
    logStderrLine(
      `anchore_policy_blocking_vulnerabilities: ${anchoreFailureMessage(err)}`,
    );
    return errorResult({
      error: true,
      message: anchoreFailureMessage(err),
    });
  }
}
