import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  getConnectionSnapshot,
  loadConnectionFromEnv,
} from "./connection.js";

function restoreEnv(
  key: "ANCHORE_URL" | "ANCHORE_TOKEN" | "ANCHORE_ACCOUNT",
  value: string | undefined,
) {
  if (value === undefined) {
    delete process.env[key];
  } else {
    process.env[key] = value;
  }
}

describe("loadConnectionFromEnv", () => {
  let origUrl: string | undefined;
  let origToken: string | undefined;
  let origAcct: string | undefined;

  beforeEach(() => {
    origUrl = process.env.ANCHORE_URL;
    origToken = process.env.ANCHORE_TOKEN;
    origAcct = process.env.ANCHORE_ACCOUNT;
    delete process.env.ANCHORE_URL;
    delete process.env.ANCHORE_TOKEN;
    delete process.env.ANCHORE_ACCOUNT;
  });

  afterEach(() => {
    restoreEnv("ANCHORE_URL", origUrl);
    restoreEnv("ANCHORE_TOKEN", origToken);
    restoreEnv("ANCHORE_ACCOUNT", origAcct);
  });

  it("loads required vars and strips trailing slash on URL", () => {
    process.env.ANCHORE_URL = "https://anchore.example.com/";
    process.env.ANCHORE_TOKEN = "secret-token";
    const c = loadConnectionFromEnv();
    expect(c.baseUrl).toBe("https://anchore.example.com");
    expect(c.username).toBe("_api_key");
    expect(c.password).toBe("secret-token");
    expect(c.account).toBeUndefined();
  });

  it("includes optional account", () => {
    process.env.ANCHORE_URL = "https://a.example.com";
    process.env.ANCHORE_TOKEN = "t";
    process.env.ANCHORE_ACCOUNT = " myacct ";
    const c = loadConnectionFromEnv();
    expect(c.account).toBe("myacct");
  });

  it("omits account when unset or empty", () => {
    process.env.ANCHORE_URL = "https://a.example.com";
    process.env.ANCHORE_TOKEN = "t";
    process.env.ANCHORE_ACCOUNT = "   ";
    const c = loadConnectionFromEnv();
    expect(c.account).toBeUndefined();
  });

  it("throws when ANCHORE_URL missing", () => {
    process.env.ANCHORE_TOKEN = "t";
    expect(() => loadConnectionFromEnv()).toThrow(/ANCHORE_URL/);
  });

  it("throws when URL is not https", () => {
    process.env.ANCHORE_URL = "http://insecure.example.com";
    process.env.ANCHORE_TOKEN = "t";
    expect(() => loadConnectionFromEnv()).toThrow(/https/);
  });

  it("throws when ANCHORE_TOKEN missing", () => {
    process.env.ANCHORE_URL = "https://a.example.com";
    expect(() => loadConnectionFromEnv()).toThrow(/ANCHORE_TOKEN/);
  });
});

describe("getConnectionSnapshot", () => {
  it("returns non-secret fields", () => {
    const snap = getConnectionSnapshot({
      baseUrl: "https://x.com",
      username: "_api_key",
      password: "secret",
      account: "acct",
    });
    expect(snap).toEqual({
      baseUrl: "https://x.com",
      account: "acct",
    });
  });

  it("uses null account when absent", () => {
    const snap = getConnectionSnapshot({
      baseUrl: "https://x.com",
      username: "_api_key",
      password: "secret",
    });
    expect(snap.account).toBeNull();
  });
});
