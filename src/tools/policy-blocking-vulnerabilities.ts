import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  imagePolicyCheckPath,
  imageVulnerabilitiesPath,
} from "../anchore/api-paths.js";
import { createAnchoreClient } from "../anchore/client.js";
import { AnchoreError } from "../anchore/errors.js";
import {
  selectImageForPolicyBlockingReport,
  type PolicyBlockingImageLocator,
  type SelectedImage,
} from "../anchore/image-selection.js";
import {
  extractPolicyBlockingFindings,
  hasPolicyBlockingAction,
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
export const POLICY_BLOCKING_VULN_EVIDENCE_MAX_RESPONSE_BYTES =
  20 * 1024 * 1024;
const UNEXPECTED_POLICY_BLOCKING_FAILURE_MESSAGE =
  "Unexpected error while building policy blocking vulnerabilities.";
const IMAGE_SELECTION_FAILURE_MESSAGE =
  "Image selection failed before policy evaluation.";

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

export type PolicyBlockingVulnerabilitiesErrorStatus =
  | "image_selection_error"
  | "red_policy_without_proven_vulnerability_fix";

export type PolicyBlockingVulnerabilitiesErrorPayload = {
  error: true;
  message: string;
  policyRemediationStatus?: PolicyBlockingVulnerabilitiesErrorStatus;
  reportVersion?: typeof POLICY_BLOCKING_VULNS_REPORT_VERSION;
  selectedImage?: SelectedImage;
};

function errorResult(
  payload: PolicyBlockingVulnerabilitiesErrorPayload,
): CallToolResult {
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

function policyBlockingFailureMessage(err: unknown): string {
  if (err instanceof AnchoreError) {
    return anchoreFailureMessage(err);
  }

  return UNEXPECTED_POLICY_BLOCKING_FAILURE_MESSAGE;
}

function policyBlockingSelectionMessage(message: string): string {
  const safeMessages = new Set([
    "Supply image_registry and image_repository together.",
    "Supply exactly one of image_digest, image_reference, or the image_registry and image_repository pair.",
    "image_digest is empty.",
    "image_reference is empty.",
    "image_reference is too long.",
    "image_reference contains invalid control characters.",
    "image_reference must include a tag (registry/repo:tag).",
    "image_reference must be a fully qualified image reference (e.g. docker.io/library/nginx:latest).",
    "image_registry is empty.",
    "image_registry is too long.",
    "image_registry contains invalid control characters.",
    "image_registry must not contain '/'.",
    "image_repository is empty.",
    "image_repository is too long.",
    "image_repository contains invalid control characters.",
    "image_repository must not begin or end with '/'.",
    "image_repository must not include an image tag.",
    "No matching image row had both a digest and a reliable analysis timestamp.",
  ]);
  const safeDynamicPatterns = [
    /^Newest analyzed image is ambiguous: \d+ digests share timestamp [A-Za-z0-9:.+-]+\.$/,
    /^Image list enumeration incomplete after \d+ page\(s\)\.$/,
    /^Stopped after collecting \d+ image row\(s\) \(maxItems cap\)\.$/,
    /^Stopped after \d+ page request\(s\) \(maxPages cap\)\.$/,
  ];

  return safeMessages.has(message) ||
    safeDynamicPatterns.some((pattern) => pattern.test(message))
    ? message
    : IMAGE_SELECTION_FAILURE_MESSAGE;
}

function policyQuery(
  args: PolicyBlockingVulnerabilitiesArgs,
  selectedImage: SelectedImage,
): URLSearchParams {
  const query = new URLSearchParams();
  const tag = args.tag?.trim() || selectedImage.reference?.trim();
  if (tag) {
    query.set("tag", tag);
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
      message: policyBlockingSelectionMessage(selected.message),
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
        policyQuery(args, selected.selectedImage),
      ),
    );

    const policyStatus = policyStatusFromPayload(policyData);
    const policyHasBlockingAction = hasPolicyBlockingAction(policyData);
    if (policyStatus === "green" || (policyStatus === "unknown" && !policyHasBlockingAction)) {
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
      { maxResponseBytes: POLICY_BLOCKING_VULN_EVIDENCE_MAX_RESPONSE_BYTES },
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
        reportVersion: POLICY_BLOCKING_VULNS_REPORT_VERSION,
        selectedImage: selected.selectedImage,
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
    const message = policyBlockingFailureMessage(err);
    logStderrLine(
      `anchore_policy_blocking_vulnerabilities: ${message}`,
    );
    return errorResult({
      error: true,
      message,
    });
  }
}
