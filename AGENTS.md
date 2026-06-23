# codex-loon-rules — Agent Instructions

Personal Loon routing notes, supplemental rule lists, and validation tooling. See `README.md` for the project map.

## Agent skills

### Issue tracker

Issues are tracked across **Linear (primary, source of truth)** and **GitHub (secondary, code + PRs)**. `/triage`, `to-issues`, `to-prd`, and `qa` read/write Linear first and mirror to GitHub when code is involved. External PRs are **not** a triage surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical defaults: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix` (mapped to Linear workflow states). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout — one `CONTEXT.md` + `docs/adr/` at the repo root, created lazily by `/domain-modeling`. See `docs/agents/domain.md`.
