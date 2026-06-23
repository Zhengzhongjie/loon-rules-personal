# Issue tracker: Linear (primary) + GitHub (secondary)

This repo tracks work across two systems. **Linear is the source of truth** for issues, PRDs, and triage. **GitHub** holds the code and pull requests, and mirrors selected issues for repo-local context.

When a skill says "publish to the issue tracker", "fetch the relevant ticket", or "apply a triage label", it means **Linear** unless the item is purely a code/PR concern.

## Primary: Linear

Drive Linear through the Linear MCP server (`mcp__plugin_linear_linear__*`). Authenticate once per session via `mcp__plugin_linear_linear__authenticate` if calls fail with an auth error.

- **Create an issue / PRD**: create a Linear issue in the project's default team. Put the title in the issue title and the full body (including PRD sections) in the description.
- **Read a ticket**: fetch the Linear issue by its identifier (e.g. `LOON-42`) including comments and current workflow state.
- **List for triage**: list open issues in the team, including state, labels, and comments, so `/triage` can run its state machine.
- **Comment**: add a comment to the Linear issue.
- **Apply / change state or label**: move the issue's workflow state (see `triage-labels.md` for the role→state mapping) or apply a label.
- **Close**: move the issue to a terminal state (Done / Canceled) with a closing comment.

## Secondary: GitHub

Use the `gh` CLI for anything that lives next to the code. `gh` infers the repo from `git remote -v` when run inside the clone (`Zhengzhongjie/codex-loon-rules`).

- **Pull requests** live in GitHub. Read with `gh pr view <number> --comments` and `gh pr diff <number>`.
- **Mirror an issue to GitHub** (when code work needs a repo-local anchor): `gh issue create --title "..." --body "..."` (heredoc for multi-line bodies). Cross-link it to the Linear identifier in the body.
- **Read / list / comment / label / close** on the GitHub side: `gh issue view <n> --comments`, `gh issue list --state open --json number,title,body,labels,comments`, `gh issue comment <n> --body "..."`, `gh issue edit <n> --add-label/--remove-label "..."`, `gh issue close <n> --comment "..."`.

When an item exists in both systems, **Linear's state wins**; keep the GitHub mirror's labels/state in sync as a courtesy, not as the source of truth.

## Pull requests as a triage surface

**PRs as a request surface: no.** `/triage` does not pull external PRs into the queue. This is a personal repo where the maintainer authors the PRs. (Flip this to `yes` here and add `gh pr list` handling if the repo later accepts outside contributions.)

## When a skill says "publish to the issue tracker"

Create a **Linear** issue. Mirror to a GitHub issue only if the work is code-bound and benefits from a repo-local anchor.

## When a skill says "fetch the relevant ticket"

Fetch the **Linear** issue by identifier. If given a bare `#42`, treat it as GitHub (`gh issue view 42`, falling back to `gh pr view 42`); if given a project-prefixed id like `LOON-42`, treat it as Linear.
