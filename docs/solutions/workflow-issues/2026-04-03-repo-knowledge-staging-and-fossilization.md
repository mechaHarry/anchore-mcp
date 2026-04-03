---
title: Repo knowledge staging (MEMORY.md) and fossilization (docs/solutions)
date: 2026-04-03
module: anchore-mcp
problem_type: workflow_issue
component: development_workflow
severity: low
applies_when:
  - Onboarding a new coding agent or contributor to how compounded learnings are stored
  - Deciding where to put a note versus a full solution write-up
tags:
  - memory
  - docs-solutions
  - agents-md
  - cursor-rules
  - compound-workflow
---

# Repo knowledge staging (`MEMORY.md`) and fossilization (`docs/solutions/`)

## Context

A single flat doc or ad hoc notes do not scale: new models and humans need a **repeatable contract** for (1) fast session continuity and (2) durable, searchable institutional memory. This repo encodes that as **two layers** plus **discoverability** in agent-facing files.

## Guidance

1. **`MEMORY.md` (repository root)** — **Staging cache**: append-friendly; preferences, quick decisions, pointers. **Not** the canonical long-term record. See the file’s own header and table.

2. **`docs/solutions/<category>/`** — **Fossilized** learnings: verified problems or practices, YAML frontmatter (`module`, `tags`, `problem_type`, …), categories such as `integration-issues/`, `best-practices/`, `workflow-issues/`. Reviewable in PRs and searchable by field.

3. **Promotion rule** — When a `MEMORY.md` entry is **verified** and should outlive one chat, add a structured file under `docs/solutions/` (use **`/ce:compound`** when available for correct frontmatter and sections), then **trim or remove** the promoted content from `MEMORY.md`.

4. **Agent surfaces (discoverability)** — The contract is repeated so new sessions see it without hunting:
   - [AGENTS.md](../../../AGENTS.md) § **Knowledge flow** — authoritative rules.
   - [README.md](../../../README.md) — short pointer at the top.
   - [`.cursor/rules/knowledge-flow-memory-solutions.mdc`](../../../.cursor/rules/knowledge-flow-memory-solutions.mdc) — `alwaysApply` reminder for Cursor.

## Why This Matters

Without a clear split, everything lands in one place: either **`MEMORY.md` grows into an unreviewable wiki** or **`docs/solutions/` is bypassed** for quick notes — and search, PR review, and the Compound workflow stop working. The two-layer model keeps **speed** (staging) and **durability** (fossils) aligned.

## When to Apply

- Starting substantive work: **read `MEMORY.md`** if present; **read `AGENTS.md` § Knowledge flow**.
- After fixing a non-trivial integration or design issue: **fossilize** to `docs/solutions/`, then clean **`MEMORY.md`**.

## Examples

| Situation | Where it goes first | Next step |
|-----------|---------------------|-----------|
| “Prefer `pnpm run check` before PR” (team preference) | `MEMORY.md` bullet | After team agrees, optional short note in `AGENTS.md` or a `workflow-issues/` doc |
| “Anchore v2 returns 400 if path uses `sbom` not `sboms`” | Promote directly to `docs/solutions/integration-issues/` | Remove duplicate prose from `MEMORY.md` if any |
| Session scratch URLs | `MEMORY.md` only | Delete when stale |

## Related

- [MEMORY.md](../../../MEMORY.md) — staging cache contract (short form).
- [AGENTS.md](../../../AGENTS.md#knowledge-flow) — full rules for agents and humans.
- [docs/research/anchore-api-notes.md](../../research/anchore-api-notes.md) — API facts (separate from process, but often cross-linked from integration solution docs).
