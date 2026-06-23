# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual strings used in this repo's trackers. Because Linear is primary, each role maps to a **Linear workflow state** (the natural fit) and to a **GitHub label** for the secondary mirror.

| Role in mattpocock/skills | Linear workflow state | GitHub label (mirror) | Meaning                                  |
| ------------------------- | --------------------- | --------------------- | ---------------------------------------- |
| `needs-triage`            | `Triage`              | `needs-triage`        | Maintainer needs to evaluate this issue  |
| `needs-info`              | `Blocked` / `Backlog` | `needs-info`          | Waiting on reporter for more information |
| `ready-for-agent`         | `Todo` (AFK-ready)    | `ready-for-agent`     | Fully specified, ready for an AFK agent  |
| `ready-for-human`         | `Todo` (needs human)  | `ready-for-human`     | Requires human implementation            |
| `wontfix`                 | `Canceled`            | `wontfix`             | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), move the Linear issue to the corresponding **workflow state** above. If the issue is mirrored to GitHub, also apply the matching GitHub label string.

> `ready-for-agent` and `ready-for-human` both sit in Linear's `Todo` state; distinguish them with a Linear **label** (`ready-for-agent` / `ready-for-human`) so AFK agents can filter for their queue.

Edit the right-hand columns to match whatever vocabulary you actually use in Linear and GitHub.
