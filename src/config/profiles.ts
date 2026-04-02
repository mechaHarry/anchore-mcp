import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import {
  type AnchoreMcpConfig,
  configFileSchema,
  type ProfileEntry,
} from "./schema.js";

const CONFIG_ENV = "ANCHORE_MCP_CONFIG";

export type ResolvedProfile = ProfileEntry & {
  profileName: string;
  /** API token from the environment; never log or return in tool text. */
  password: string;
};

export type LoadConfigResult = {
  config: AnchoreMcpConfig;
  /** Absolute path we attempted to read (for user messages). */
  resolvedPath: string;
  /** True if the file existed and was parsed successfully. */
  fileFound: boolean;
};

/** Default config path when `ANCHORE_MCP_CONFIG` is unset (XDG-style on Unix). */
export function getDefaultConfigPath(): string {
  const override = process.env[CONFIG_ENV];
  if (override && override.length > 0) {
    return path.resolve(override);
  }
  if (process.platform === "win32") {
    const base = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");
    return path.join(base, "anchore-mcp", "config.yaml");
  }
  return path.join(os.homedir(), ".config", "anchore-mcp", "config.yaml");
}

/**
 * Read and validate config from disk. If the file is missing, returns an empty config
 * (no profiles) and `fileFound: false`.
 */
export function loadConfigFile(resolvedPath: string): LoadConfigResult {
  if (!fs.existsSync(resolvedPath)) {
    return {
      config: { profiles: {} },
      resolvedPath,
      fileFound: false,
    };
  }
  const text = fs.readFileSync(resolvedPath, "utf8");
  const parsed: unknown = parseYaml(text);
  const config = configFileSchema.parse(parsed);
  return { config, resolvedPath, fileFound: true };
}

export function resolvePasswordFromEnv(envName: string): string {
  const v = process.env[envName];
  if (v === undefined || v === "") {
    throw new Error(
      `Environment variable "${envName}" is not set or is empty (required for Anchore API token)`,
    );
  }
  return v;
}

export class ProfileRegistry {
  constructor(
    readonly config: AnchoreMcpConfig,
    readonly resolvedPath: string,
    readonly fileFound: boolean,
  ) {}

  /** Profile names (sorted for stable output). */
  listProfileNames(): string[] {
    return Object.keys(this.config.profiles).sort();
  }

  getDefaultProfileName(): string | null {
    return this.config.defaultProfile ?? null;
  }

  /**
   * Resolve credentials for Anchore calls. `override` selects a profile; otherwise `defaultProfile` is used.
   */
  resolve(override?: string): ResolvedProfile {
    const keys = Object.keys(this.config.profiles);
    if (keys.length === 0) {
      throw new Error(
        "No profiles are configured. Add profiles to your Anchore MCP config file.",
      );
    }
    const name = override ?? this.config.defaultProfile;
    if (!name) {
      throw new Error(
        "No profile specified and defaultProfile is not set in config.",
      );
    }
    const entry = this.config.profiles[name];
    if (!entry) {
      throw new Error(
        `Unknown profile "${name}". Known profiles: ${keys.sort().join(", ")}`,
      );
    }
    const password = resolvePasswordFromEnv(entry.passwordEnv);
    return { ...entry, profileName: name, password };
  }

  /** Non-secret snapshot for `anchore_list_profiles` and R8-style context. */
  getPublicSnapshot(): {
    profiles: string[];
    defaultProfile: string | null;
    configPath: string | null;
    configFilePresent: boolean;
    note: string;
  } {
    const profiles = this.listProfileNames();
    const note = this.buildNote(profiles.length);
    return {
      profiles,
      defaultProfile: this.getDefaultProfileName(),
      configPath: this.fileFound ? this.resolvedPath : null,
      configFilePresent: this.fileFound,
      note,
    };
  }

  private buildNote(profileCount: number): string {
    if (!this.fileFound) {
      return `No config file found at ${this.resolvedPath}. Set ${CONFIG_ENV} or create that file (see config.example.yaml in the repo).`;
    }
    if (profileCount === 0) {
      return "Config file exists but no profiles are defined. Add entries under `profiles`.";
    }
    return "Profiles loaded from config.";
  }
}
