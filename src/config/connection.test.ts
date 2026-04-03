import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  getConnectionSnapshot,
  loadConnectionFromEnv,
} from "./connection.js";

function restoreEnv(
  key:
    | "ANCHORE_URL"
    | "ANCHORE_TOKEN"
    | "ANCHORE_ACCOUNT"
    | "ANCHORE_API_VERSION",
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
  let origVer: string | undefined;

  beforeEach(() => {
    origUrl = process.env.ANCHORE_URL;
    origToken = process.env.ANCHORE_TOKEN;
    origAcct = process.env.ANCHORE_ACCOUNT;
    origVer = process.env.ANCHORE_API_VERSION;
    delete process.env.ANCHORE_URL;
    delete process.env.ANCHORE_TOKEN;
    delete process.env.ANCHORE_ACCOUNT;
    delete process.env.ANCHORE_API_VERSION;
  });

  afterEach(() => {
    restoreEnv("ANCHORE_URL", origUrl);
    restoreEnv("ANCHORE_TOKEN", origToken);
    restoreEnv("ANCHORE_ACCOUNT", origAcct);
    restoreEnv("ANCHORE_API_VERSION", origVer);
  });

  it("loads required vars and strips trailing slash on URL", () => {
    process.env.ANCHORE_URL = "https://anchore.example.com/";
    process.env.ANCHORE_TOKEN = "secret-token";
    const c = loadConnectionFromEnv();
    expect(c.baseUrl).toBe("https://anchore.example.com");
    expect(c.username).toBe("_api_key");
    expect(c.password).toBe("secret-token");
    expect(c.account).toBeUndefined();
    expect(c.apiVersion).toBe("v2");
  });

  it("defaults apiVersion to v2 when ANCHORE_API_VERSION is unset", () => {
    process.env.ANCHORE_URL = "https://a.example.com";
    process.env.ANCHORE_TOKEN = "t";
    expect(loadConnectionFromEnv().apiVersion).toBe("v2");
  });

  it("honors ANCHORE_API_VERSION=v1", () => {
    process.env.ANCHORE_URL = "https://a.example.com";
    process.env.ANCHORE_TOKEN = "t";
    process.env.ANCHORE_API_VERSION = "v1";
    expect(loadConnectionFromEnv().apiVersion).toBe("v1");
  });

  it("throws when ANCHORE_API_VERSION is invalid", () => {
    process.env.ANCHORE_URL = "https://a.example.com";
    process.env.ANCHORE_TOKEN = "t";
    process.env.ANCHORE_API_VERSION = "v3";
    expect(() => loadConnectionFromEnv()).toThrow();
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
      apiVersion: "v2",
    });
    expect(snap).toEqual({
      baseUrl: "https://x.com",
      account: "acct",
      apiVersion: "v2",
    });
  });

  it("uses null account when absent", () => {
    const snap = getConnectionSnapshot({
      baseUrl: "https://x.com",
      username: "_api_key",
      password: "secret",
      apiVersion: "v1",
    });
    expect(snap.account).toBeNull();
    expect(snap.apiVersion).toBe("v1");
  });
});
