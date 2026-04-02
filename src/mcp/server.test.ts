import { describe, it, expect } from "vitest";
import { createMcpServer, getProfilesSnapshot } from "./server.js";

describe("getProfilesSnapshot", () => {
  it("returns empty profiles until Unit 2", () => {
    const snap = getProfilesSnapshot();
    expect(snap.profiles).toEqual([]);
    expect(snap.defaultProfile).toBeNull();
    expect(snap.note).toContain("Unit 2");
  });
});

describe("createMcpServer", () => {
  it("creates an McpServer instance", () => {
    const server = createMcpServer();
    expect(server).toBeDefined();
    expect(server.isConnected()).toBe(false);
  });
});
