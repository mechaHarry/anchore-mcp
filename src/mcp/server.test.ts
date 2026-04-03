import { describe, it, expect } from "vitest";
import type { ResolvedAnchoreConnection } from "../config/connection.js";
import { createMcpServer, getConnectionInfo } from "./server.js";

const sampleConnection: ResolvedAnchoreConnection = {
  baseUrl: "https://anchore.example.com",
  username: "_api_key",
  password: "secret",
  account: "myacct",
};

describe("getConnectionInfo", () => {
  it("returns non-secret fields only", () => {
    const info = getConnectionInfo(sampleConnection);
    expect(info).toEqual({
      baseUrl: "https://anchore.example.com",
      account: "myacct",
    });
  });
});

describe("createMcpServer", () => {
  it("creates an McpServer instance", () => {
    const server = createMcpServer(sampleConnection);
    expect(server).toBeDefined();
    expect(server.isConnected()).toBe(false);
  });
});
