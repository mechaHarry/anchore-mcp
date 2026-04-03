# MEMORY — staging cache (read `AGENTS.md` for promotion rules)

This file is the **working cache** for immediate learnings, preferences, and session-local context. It is **not** the canonical, long-term record for the repo.

## Two layers (do not conflate them)

| Layer | Purpose |
|--------|---------|
| **`MEMORY.md`** | Fast append: preferences, “we decided X”, URLs, reminders, raw notes. Optimized for **the next session** and **the next model** to pick up quickly. |
| **`docs/solutions/<category>/`** | **Fossilized** learnings: verified behavior, reproducible guidance, YAML frontmatter (`module`, `tags`, `problem_type`, …), reviewable in PRs. This is the **durable** compounded knowledge base. |

## Fossilization rule

When a note here represents a **verified** fix, integration quirk, or recurring practice that should survive past one chat:

1. **Promote** it into `docs/solutions/` as a structured markdown file (category per topic — see [AGENTS.md](AGENTS.md)).
2. **Trim or delete** the corresponding bullets in this file so `MEMORY.md` stays a thin staging area, not a second wiki.

Optional tooling: the Compound Engineering **`/ce:compound`** workflow produces the right shape (frontmatter + sections); use it when available.

## Entries

*(Append below. Dated blocks or reverse-chronological order work well.)*

### 2026-04-03 (session — optional staging notes)

- **Relative links in `docs/solutions/<subdir>/`:** Files one level under `docs/solutions/` use `../../` to reach `docs/` and `../../../` to reach repo root. The workflow learning had root links wrong (`../../`); fixed in compound-refresh — when linking to `AGENTS.md`, `README.md`, `MEMORY.md`, or `.cursor/` from `docs/solutions/*/*.md`, count path segments.
- **Already fossilized (no action needed):** Knowledge flow (MEMORY → `docs/solutions/`), Cursor `alwaysApply` rule, workflow doc `docs/solutions/workflow-issues/2026-04-03-repo-knowledge-staging-and-fossilization.md`. Trim this block after the next PR if nothing here is still operationally useful.
