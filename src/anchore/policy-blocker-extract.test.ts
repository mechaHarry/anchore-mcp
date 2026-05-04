import { describe, expect, it } from "vitest";
import {
  extractPolicyBlockingFindings,
  policyStatusFromPayload,
} from "./policy-blocker-extract.js";

describe("policyStatusFromPayload", () => {
  it("recognizes green policy states", () => {
    expect(policyStatusFromPayload({ status: "pass" })).toBe("green");
    expect(policyStatusFromPayload({ result: { status: "green" } })).toBe("green");
  });

  it("recognizes red policy states", () => {
    expect(policyStatusFromPayload({ status: "fail" })).toBe("red");
    expect(policyStatusFromPayload({ result: { status: "red" } })).toBe("red");
  });

  it("returns unknown for unsupported status shapes", () => {
    expect(policyStatusFromPayload({ outcome: "not-a-policy-status" })).toBe("unknown");
  });
});

describe("extractPolicyBlockingFindings", () => {
  it("extracts vulnerability id blockers with policy metadata", () => {
    const findings = extractPolicyBlockingFindings({
      status: "fail",
      findings: [
        {
          gate: "vulnerabilities",
          trigger: "package",
          action: "stop",
          vulnerability_id: "CVE-2026-1234",
          package_name: "openssl",
          package_version: "1.0.1",
          reason: "Policy stops on this CVE",
        },
      ],
    });

    expect(findings).toEqual([
      {
        vulnerabilityId: "CVE-2026-1234",
        packageName: "openssl",
        packageVersion: "1.0.1",
        gate: "vulnerabilities",
        trigger: "package",
        reason: "Policy stops on this CVE",
        sourceRef: "findings[0]",
      },
    ]);
  });

  it("extracts exact package blockers without a CVE id", () => {
    const findings = extractPolicyBlockingFindings({
      status: "fail",
      policy: {
        checks: [
          {
            gate: "vulnerabilities",
            trigger: "package",
            action: "fail",
            packageName: "libssl",
            packageVersion: "3.0.0",
          },
        ],
      },
    });

    expect(findings).toEqual([
      {
        packageName: "libssl",
        packageVersion: "3.0.0",
        gate: "vulnerabilities",
        trigger: "package",
        sourceRef: "policy.checks[0]",
      },
    ]);
  });

  it("treats any blocking action, status, or result as blocking", () => {
    const findings = extractPolicyBlockingFindings({
      findings: [
        {
          action: "warn",
          status: "fail",
          cve: "CVE-2026-0001",
        },
      ],
    });

    expect(findings).toEqual([
      {
        vulnerabilityId: "CVE-2026-0001",
        sourceRef: "findings[0]",
      },
    ]);
  });

  it("does not treat policy_action as a blocking action field", () => {
    const findings = extractPolicyBlockingFindings({
      findings: [{ policy_action: "stop", cve: "CVE-2026-0002" }],
    });

    expect(findings).toEqual([]);
  });

  it("does not treat generic ids as vulnerability evidence without a vulnerability gate", () => {
    const findings = extractPolicyBlockingFindings({
      findings: [{ action: "stop", id: "policy-row-1" }],
    });

    expect(findings).toEqual([]);
  });

  it("ignores non-blocking and non-vulnerability policy findings", () => {
    const findings = extractPolicyBlockingFindings({
      status: "fail",
      findings: [
        {
          gate: "dockerfile",
          trigger: "instruction",
          action: "stop",
          package_name: "openssl",
          package_version: "1.0.1",
        },
        { gate: "vulnerabilities", trigger: "package", action: "go" },
      ],
    });

    expect(findings).toEqual([]);
  });
});
