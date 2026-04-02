import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  loadConfigFile,
  ProfileRegistry,
  resolvePasswordFromEnv,
} from "./profiles.js";

describe("loadConfigFile", () => {
  let tmpDir: string;
  let configPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "anchore-mcp-"));
    configPath = path.join(tmpDir, "config.yaml");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns empty profiles when file is missing", () => {
    const r = loadConfigFile(path.join(tmpDir, "nope.yaml"));
    expect(r.fileFound).toBe(false);
    expect(r.config.profiles).toEqual({});
  });

  it("loads multiple profiles and defaultProfile", () => {
    fs.writeFileSync(
      configPath,
      `
defaultProfile: prod
profiles:
  prod:
    baseUrl: https://a.example.com
    username: _api_key
    passwordEnv: TOKEN_A
  lab:
    baseUrl: https://b.example.com
    username: _api_key
    passwordEnv: TOKEN_B
`,
      "utf8",
    );
    const r = loadConfigFile(configPath);
    expect(r.fileFound).toBe(true);
    expect(r.config.defaultProfile).toBe("prod");
    expect(Object.keys(r.config.profiles).sort()).toEqual(["lab", "prod"]);
  });

  it("rejects config when defaultProfile is missing but profiles exist", () => {
    fs.writeFileSync(
      configPath,
      `
profiles:
  prod:
    baseUrl: https://a.example.com
    username: _api_key
    passwordEnv: TOKEN_A
`,
      "utf8",
    );
    expect(() => loadConfigFile(configPath)).toThrow(/defaultProfile/);
  });

  it("rejects unknown username for token auth", () => {
    fs.writeFileSync(
      configPath,
      `
defaultProfile: prod
profiles:
  prod:
    baseUrl: https://a.example.com
    username: admin
    passwordEnv: TOKEN_A
`,
      "utf8",
    );
    expect(() => loadConfigFile(configPath)).toThrow();
  });
});

describe("ProfileRegistry", () => {
  const baseConfig = {
    defaultProfile: "prod" as const,
    profiles: {
      prod: {
        baseUrl: "https://a.example.com",
        username: "_api_key" as const,
        passwordEnv: "MY_TOKEN",
      },
      lab: {
        baseUrl: "https://b.example.com",
        username: "_api_key" as const,
        passwordEnv: "LAB_TOKEN",
      },
    },
  };

  it("resolve uses default profile when override omitted", () => {
    vi.stubEnv("MY_TOKEN", "secret-prod");
    vi.stubEnv("LAB_TOKEN", "secret-lab");
    const reg = new ProfileRegistry(baseConfig, "/x/config.yaml", true);
    const r = reg.resolve();
    expect(r.profileName).toBe("prod");
    expect(r.password).toBe("secret-prod");
    expect(r.baseUrl).toBe("https://a.example.com");
    vi.unstubAllEnvs();
  });

  it("resolve uses override profile", () => {
    vi.stubEnv("MY_TOKEN", "secret-prod");
    vi.stubEnv("LAB_TOKEN", "secret-lab");
    const reg = new ProfileRegistry(baseConfig, "/x/config.yaml", true);
    const r = reg.resolve("lab");
    expect(r.profileName).toBe("lab");
    expect(r.password).toBe("secret-lab");
    vi.unstubAllEnvs();
  });

  it("resolve throws for unknown profile", () => {
    vi.stubEnv("MY_TOKEN", "x");
    vi.stubEnv("LAB_TOKEN", "y");
    const reg = new ProfileRegistry(baseConfig, "/x/config.yaml", true);
    expect(() => reg.resolve("missing")).toThrow(/Unknown profile/);
    vi.unstubAllEnvs();
  });

  it("resolve throws when password env is missing (message does not leak token)", () => {
    vi.stubEnv("MY_TOKEN", "");
    vi.stubEnv("LAB_TOKEN", "");
    const reg = new ProfileRegistry(baseConfig, "/x/config.yaml", true);
    try {
      reg.resolve("prod");
      expect.fail("expected throw");
    } catch (e) {
      expect(String(e)).toMatch(/MY_TOKEN/);
      expect(String(e).toLowerCase()).not.toContain("secret");
    }
    vi.unstubAllEnvs();
  });

  it("resolve throws when no profiles configured", () => {
    const reg = new ProfileRegistry({ profiles: {} }, "/x/config.yaml", true);
    expect(() => reg.resolve()).toThrow(/No profiles/);
  });

  it("getPublicSnapshot lists names without secrets", () => {
    const reg = new ProfileRegistry(baseConfig, "/x/config.yaml", true);
    const snap = reg.getPublicSnapshot();
    expect(snap.profiles).toEqual(["lab", "prod"]);
    expect(snap.defaultProfile).toBe("prod");
    expect(JSON.stringify(snap)).not.toMatch(/secret|TOKEN/i);
  });
});

describe("resolvePasswordFromEnv", () => {
  it("throws a safe message when unset", () => {
    vi.stubEnv("MISSING_TOKEN_XYZ", undefined);
    expect(() => resolvePasswordFromEnv("MISSING_TOKEN_XYZ")).toThrow(
      /MISSING_TOKEN_XYZ/,
    );
    vi.unstubAllEnvs();
  });
});
