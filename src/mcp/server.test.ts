import { describe, it, expect } from "vitest";
import { ProfileRegistry } from "../config/profiles.js";
import { createMcpServer, getProfilesSnapshot } from "./server.js";

const emptyRegistry = new ProfileRegistry({ profiles: {} }, "/tmp/x.yaml", false);

describe("getProfilesSnapshot", () => {
  it("returns empty profiles when no config file", () => {
    const snap = getProfilesSnapshot(emptyRegistry);
    expect(snap.profiles).toEqual([]);
    expect(snap.defaultProfile).toBeNull();
    expect(snap.configFilePresent).toBe(false);
    expect(snap.note).toMatch(/No config file/);
  });
});

describe("createMcpServer", () => {
  it("creates an McpServer instance", () => {
    const server = createMcpServer(emptyRegistry);
    expect(server).toBeDefined();
    expect(server.isConnected()).toBe(false);
  });
});
