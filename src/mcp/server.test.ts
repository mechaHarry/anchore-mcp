import { describe, it, expect } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { createMcpServer, getConnectionInfo } from "./server.js";

const sampleConnection: ResolvedAnchoreConnection = {
  baseUrl: "https://anchore.example.com",
  username: "_api_key",
  password: "secret",
  account: "myacct",
  apiVersion: "v2",
};

describe("getConnectionInfo", () => {
  it("returns non-secret fields only", () => {
    const info = getConnectionInfo(sampleConnection);
    expect(info).toEqual({
      baseUrl: "https://anchore.example.com",
      account: "myacct",
      apiVersion: "v2",
    });
  });
});

describe("createMcpServer", () => {
  it("creates an McpServer instance", () => {
    const server = createMcpServer({ connection: sampleConnection });
    expect(server).toBeDefined();
    expect(server.isConnected()).toBe(false);
  });

  it("registers the policy-blocking vulnerability tool", () => {
    const server = createMcpServer({ connection: sampleConnection });
    const registered = Object.keys(
      (
        server as unknown as {
          _registeredTools: Record<string, unknown>;
        }
      )._registeredTools,
    );

    expect(registered).toContain("anchore_policy_blocking_vulnerabilities");
  });

  it("publishes the component-pair locator contract", () => {
    const server = createMcpServer({ connection: sampleConnection });
    const tool = (
      server as unknown as {
        _registeredTools: Record<
          string,
          {
            description?: string;
            inputSchema?: {
              shape: Record<string, { description?: string }>;
            };
          }
        >;
      }
    )._registeredTools.anchore_policy_blocking_vulnerabilities;

    expect(tool.description).toContain(
      "Pass exactly one locator mode: image_digest, image_reference, or image_registry + image_repository.",
    );
    expect(Object.keys(tool.inputSchema?.shape ?? {})).toEqual(
      expect.arrayContaining([
        "image_digest",
        "image_reference",
        "image_registry",
        "image_repository",
      ]),
    );
    expect(tool.inputSchema?.shape.image_registry?.description).toBe(
      "Anchore registry component; requires image_repository.",
    );
    expect(tool.inputSchema?.shape.image_repository?.description).toBe(
      "Anchore repository component without registry or tag; requires image_registry.",
    );
  });
});
