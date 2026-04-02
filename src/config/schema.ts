import { z } from "zod";

/** One Anchore deployment (R12: API token via Basic auth with username `_api_key`). */
export const profileEntrySchema = z.object({
  baseUrl: z.string().url(),
  username: z.literal("_api_key"),
  /** Name of a process env var holding the API token (never the token itself). */
  passwordEnv: z.string().min(1),
  /** Optional Anchore account / demarcation (R3/R12). */
  account: z.string().min(1).optional(),
});

export const configFileSchema = z
  .object({
    /** Required when `profiles` is non-empty. */
    defaultProfile: z.string().min(1).optional(),
    profiles: z.record(z.string(), profileEntrySchema),
  })
  .superRefine((data, ctx) => {
    const names = Object.keys(data.profiles);
    if (names.length === 0) {
      return;
    }
    if (!data.defaultProfile) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "defaultProfile is required when at least one profile is defined",
      });
      return;
    }
    if (!names.includes(data.defaultProfile)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `defaultProfile "${data.defaultProfile}" must match a key in profiles (known: ${names.join(", ")})`,
      });
    }
  });

export type ProfileEntry = z.infer<typeof profileEntrySchema>;
export type AnchoreMcpConfig = z.infer<typeof configFileSchema>;
