---
description: Competing bug-hunter agents scan your Python project for live-readiness issues — with a points leaderboard
argument-hint: "[--quick] [--hunter NAME] [--leaderboard] [--fix]"
allowed-tools: Bash(python*), Read, Write, Edit, Glob, Grep
---

# Bug Swarm Hunters — /bug-hunt

You are running the **Bug Swarm Hunters** arena. Specialized agents compete to find live-readiness bugs that static analysis misses.

## Parse arguments

- `--quick` → skip LLM jury, raw findings only
- `--hunter NAME` → run only the named hunter (schema, boundary, circular, timewindow, process, signalflow)
- `--leaderboard` → only show current leaderboard, no hunt
- `--fix` → write proposals for all confirmed findings

## Phase 1 — Setup

Check if `core/bug_hunter_arena.py` exists in the current project under `core/` or `shared/`.
If not, copy from this plugin's `core/` directory.

Ensure the `hunters/` directory exists with all 6 hunter files.

## Phase 2 — Hunt

Run the arena:

```bash
PYTHONPATH=. python -c "
from core.bug_hunter_arena import run_arena
result = run_arena(use_llm_jury=$USE_LLM, write_proposals=$WRITE_PROPOSALS)
print(result)
"
```

If `--hunter NAME` was given, run only that hunter:
```bash
PYTHONPATH=. python -c "
from hunters.{name}_hunter import {Name}Hunter
from core.bug_hunter_arena import BugHunterArena
from pathlib import Path
arena = BugHunterArena(Path('.'))
result = arena.run([{Name}Hunter()], use_llm_jury=$USE_LLM)
print(result)
"
```

## Phase 3 — Jury

Without `--quick`: the LLM (Claude) reviews the top findings.
For each finding rated `critical` or `high`, verify:
- Is this a realistic bug in this codebase?
- Or a false positive (e.g. test file, intentional pattern)?

Update confirmed/false_positive flags accordingly.

## Phase 4 — Reward

Print the updated leaderboard with points:
- +10 per confirmed bug
- +5 per proposal written
- -3 per false positive
- ×2 severity bonus for critical

## Phase 5 — Report

Write `BUG_HUNT_REPORT.md` with:
- Summary table (hunter, findings, severity)
- Top 5 most critical findings with file:line and suggested fix
- Leaderboard

## If --leaderboard only

```bash
cat .bug_hunters/leaderboard.json
```

Format and display, no hunting.

## Usage examples

```
/bug-hunt                    # Full run with LLM jury
/bug-hunt --quick            # No LLM, raw findings
/bug-hunt --hunter schema    # Only SchemaHunter
/bug-hunt --leaderboard      # Show leaderboard only
/bug-hunt --fix              # Write proposals for all findings
```
