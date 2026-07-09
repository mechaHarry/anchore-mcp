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

*(No active staging notes.)*
