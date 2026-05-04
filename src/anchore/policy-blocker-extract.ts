export type PolicyStatus = "green" | "red" | "unknown";

export type PolicyBlockingFinding = {
  vulnerabilityId?: string;
  packageName?: string;
  packageVersion?: string;
  gate?: string;
  trigger?: string;
  reason?: string;
  sourceRef: string;
};

const GREEN_STATUSES = new Set(["pass", "passed", "green", "allow", "allowed", "ok"]);
const RED_STATUSES = new Set(["fail", "failed", "red", "deny", "denied", "stop", "stopped"]);
const BLOCK_ACTIONS = new Set(["stop", "fail", "failed", "deny", "denied", "block", "blocked"]);
const VULNERABILITY_GATES = new Set(["vulnerability", "vulnerabilities", "vuln", "vulns"]);

const STATUS_KEYS = ["status", "result"] as const;
const VULNERABILITY_ID_KEYS = [
  "vulnerability_id",
  "vulnerabilityId",
  "vuln_id",
  "vulnId",
  "vuln",
  "cve",
  "id",
] as const;
const PACKAGE_NAME_KEYS = ["package_name", "packageName", "pkg_name", "pkgName", "package"] as const;
const PACKAGE_VERSION_KEYS = [
  "package_version",
  "packageVersion",
  "pkg_version",
  "pkgVersion",
  "installed_version",
  "installedVersion",
  "version",
] as const;
const REASON_KEYS = ["reason", "message", "description"] as const;

type JsonObject = Record<string, unknown>;

export function policyStatusFromPayload(payload: unknown): PolicyStatus {
  for (const value of walkValues(payload)) {
    const status = statusFromValue(value);
    if (status !== "unknown") {
      return status;
    }
  }

  return "unknown";
}

export function extractPolicyBlockingFindings(payload: unknown): PolicyBlockingFinding[] {
  const findings: PolicyBlockingFinding[] = [];

  for (const { value, sourceRef } of walkObjects(payload)) {
    const blockAction = findFirstString(value, ["action", "status", "result"]);
    if (!blockAction || !BLOCK_ACTIONS.has(normalize(blockAction))) {
      continue;
    }

    const gate = findFirstString(value, ["gate"]);
    if (gate && !VULNERABILITY_GATES.has(normalize(gate))) {
      continue;
    }

    const vulnerabilityId = findFirstString(value, VULNERABILITY_ID_KEYS);
    const packageName = findFirstString(value, PACKAGE_NAME_KEYS);
    const packageVersion = findFirstString(value, PACKAGE_VERSION_KEYS);

    if (!vulnerabilityId && (!packageName || !packageVersion)) {
      continue;
    }

    const finding: PolicyBlockingFinding = { sourceRef };

    if (vulnerabilityId) {
      finding.vulnerabilityId = vulnerabilityId;
    }
    if (packageName) {
      finding.packageName = packageName;
    }
    if (packageVersion) {
      finding.packageVersion = packageVersion;
    }
    if (gate) {
      finding.gate = gate;
    }

    const trigger = findFirstString(value, ["trigger"]);
    if (trigger) {
      finding.trigger = trigger;
    }

    const reason = findFirstString(value, REASON_KEYS);
    if (reason) {
      finding.reason = reason;
    }

    findings.push(finding);
  }

  return findings;
}

function statusFromValue(value: unknown): PolicyStatus {
  if (typeof value !== "string") {
    return "unknown";
  }

  const normalized = normalize(value);
  if (GREEN_STATUSES.has(normalized)) {
    return "green";
  }
  if (RED_STATUSES.has(normalized)) {
    return "red";
  }

  return "unknown";
}

function* walkValues(payload: unknown): Generator<unknown> {
  const seen = new WeakSet<object>();
  const stack = [payload];

  while (stack.length > 0) {
    const value = stack.pop();
    if (Array.isArray(value)) {
      if (seen.has(value)) {
        continue;
      }
      seen.add(value);

      for (let index = value.length - 1; index >= 0; index -= 1) {
        stack.push(value[index]);
      }
      continue;
    }

    if (!isObject(value)) {
      continue;
    }
    if (seen.has(value)) {
      continue;
    }
    seen.add(value);

    for (const key of STATUS_KEYS) {
      if (key in value) {
        yield value[key];
      }
    }

    const entries = Object.entries(value);
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      stack.push(entries[index]?.[1]);
    }
  }
}

function* walkObjects(payload: unknown): Generator<{ value: JsonObject; sourceRef: string }> {
  const seen = new WeakSet<object>();
  const stack: Array<{ value: unknown; sourceRef: string }> = [{ value: payload, sourceRef: "$" }];

  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) {
      continue;
    }

    if (Array.isArray(current.value)) {
      if (seen.has(current.value)) {
        continue;
      }
      seen.add(current.value);

      for (let index = current.value.length - 1; index >= 0; index -= 1) {
        stack.push({
          value: current.value[index],
          sourceRef: `${current.sourceRef}[${index}]`,
        });
      }
      continue;
    }

    if (!isObject(current.value)) {
      continue;
    }
    if (seen.has(current.value)) {
      continue;
    }
    seen.add(current.value);

    yield current;

    const entries = Object.entries(current.value);
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const entry = entries[index];
      if (!entry) {
        continue;
      }

      const [key, value] = entry;
      stack.push({
        value,
        sourceRef: current.sourceRef === "$" ? key : `${current.sourceRef}.${key}`,
      });
    }
  }
}

function findFirstString(object: JsonObject, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = stringFromValue(object[key]);
    if (value) {
      return value;
    }
  }

  return undefined;
}

function stringFromValue(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

  return undefined;
}

function normalize(value: string): string {
  return value.trim().toLowerCase();
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
