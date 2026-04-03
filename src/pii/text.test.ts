import { describe, it, expect } from "vitest";
import { maskPiiText } from "./mask.js";
import { prepareTextualToolText } from "./warn.js";

describe("maskPiiText", () => {
  it("masks email-like substrings and records kind", () => {
    const { masked, kinds } = maskPiiText("Owner: alice@company.example wrote this.");
    expect(masked).toContain("[email redacted]");
    expect(masked).not.toContain("company.example");
    expect(kinds).toContain("email");
  });

  it("masks SSN-like patterns", () => {
    const { masked, kinds } = maskPiiText("ID 123-45-6789 on file");
    expect(masked).toContain("[id redacted]");
    expect(masked).not.toContain("6789");
    expect(kinds).toContain("ssn_like");
  });
});

describe("prepareTextualToolText (R14)", () => {
  it("returns masked text and non-empty warnings when PII heuristics match", () => {
    const { text, warnings } = prepareTextualToolText(
      "Reach me at user.name@example.org today.",
    );
    expect(text).toContain("[email redacted]");
    expect(warnings.length).toBeGreaterThan(0);
    expect(warnings[0]).toMatch(/mask|masked|distribution|trust/i);
  });

  it("leaves benign text unchanged with no warnings", () => {
    const { text, warnings } = prepareTextualToolText("No PII here — list empty.");
    expect(text).toBe("No PII here — list empty.");
    expect(warnings).toEqual([]);
  });
});
