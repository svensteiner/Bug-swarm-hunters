# Bug Swarm Hunters 🐛🏆

**Competing AI agents hunt for live-readiness bugs in Python projects — with a points leaderboard.**

Six specialized hunter agents run in parallel, each targeting a different class of runtime bug that static analysis misses. An LLM jury confirms findings. Points are awarded for confirmed bugs. A leaderboard tracks which hunter is most valuable.

> Built as a Claude Code plugin. Works standalone too.

---

## Why?

Linters catch syntax. Type checkers catch type errors. But these bugs slip through:

| Bug Class | Example |
|-----------|---------|
| **Data Boundary** | `if len(df) >= 200:` — API only returns 100 rows |
| **Schema Mismatch** | `cls(**data)` — TypeError when upstream adds new fields |
| **Circular State** | MCM reads density → density=0 → MCM=UNFAVORABLE → no trades → density stays 0 |
| **Time Window** | `cooldown = 86400` — 24h freeze, system never adapts |
| **Process Leak** | `Process()` without `terminate()` in finally — zombie on Windows |
| **Signal Starvation** | MCM-Gate + EPM-Filter + min_score=8 → 0% of signals pass |

---

## Quickstart

```bash
pip install bug-swarm-hunters   # coming soon
# or
git clone https://github.com/svensteiner/Bug-swarm-hunters
cd Bug-swarm-hunters
```

**Run on any Python project:**
```bash
PYTHONPATH=. python -c "
from core.bug_hunter_arena import run_arena
from pathlib import Path
result = run_arena(Path('/path/to/your/project'), use_llm_jury=False)
print(result)
"
```

**As a Claude Code skill** (after installing the plugin):
```
/bug-hunt                    # Full run with LLM jury
/bug-hunt --quick            # No LLM, raw findings only
/bug-hunt --hunter schema    # Only SchemaHunter
/bug-hunt --leaderboard      # Show leaderboard
/bug-hunt --fix              # Write proposals for all findings
```

---

## The 6 Hunters

### DataBoundaryHunter
Scans for hardcoded data size assumptions via AST.
```python
# Finds this:
if len(df) >= 200:   # What if the API only returns 100?
    compute_sma200(df)

# Also finds:
ta.sma(df, length=200)  # Hardcoded period
```

### SchemaHunter
Finds `cls(**data)` without key filtering — the silent killer.
```python
# Finds this (CRITICAL):
def from_dict(cls, data):
    return cls(**data)  # TypeError if upstream adds new fields

# Expects this:
known = {f.name for f in dataclasses.fields(cls)}
return cls(**{k: v for k, v in data.items() if k in known})
```

### CircularStateHunter
Detects A→B→A feedback deadlocks in state files and code.
```
MCM reads density=0 → MCM=UNFAVORABLE → no trading
→ density stays 0 → MCM=UNFAVORABLE → ... (stuck forever)
```

### TimeWindowHunter
Finds cooldowns that are too long for fast-feedback loops.
```python
# Finds this:
COOLDOWN_HOURS = 24.0  # In paper-trading: system never learns
```

### ProcessHunter
Detects `Process()/Thread()` without `terminate()` in finally blocks.
```python
# Finds this:
p = Process(target=worker)
p.start()
# no p.terminate() → zombie process on Windows!
```

### SignalFlowHunter
Analyzes config files for gate combinations that block 100% of signals.
```
MCM-Gate=True + EPM-Filter=True + min_score=8
→ Signal must pass all 3 gates → 0% pass rate
```

---

## Points System

| Event | Points |
|-------|--------|
| Bug confirmed (LLM Jury) | +10 |
| Proposal written | +5 |
| False positive | -3 |
| Severity = critical | ×2 bonus |

Leaderboard stored in `.bug_hunters/leaderboard.json`.

---

## LLM Jury

Set `OPENAI_API_KEY` to enable LLM-based verification.
Uses `gpt-4.1-mini` by default (override with `LLM_FAST_MODEL`).

Without API key: all findings are confirmed as unverified (proposals still written).

---

## Extend with Custom Hunters

```python
from core.base_hunter import BaseHunter, BugFinding
from pathlib import Path

class MyCustomHunter(BaseHunter):
    name = "MyHunter"
    specialty = "my_category"
    description = "What I look for"

    def hunt(self, project_root: Path) -> list[BugFinding]:
        findings = []
        # ... your detection logic ...
        findings.append(self._make_finding(
            severity="high",
            file_path="src/module.py",
            line_number=42,
            description="Found a problem",
            evidence="the problematic code",
            suggested_fix="How to fix it",
        ))
        return findings
```

---

## Trading Bot Adapter

For projects using governance-based proposal workflows:

```python
from adapters.tradingbot_adapter import run_tradingbot_hunt
from pathlib import Path

result = run_tradingbot_hunt(Path("/path/to/tradingbot"))
# Proposals written to results/proposals/bug_*.json
```

---

## Directory Structure

```
bug-swarm-hunters/
├── .claude-plugin/
│   └── plugin.json          # Claude Code plugin manifest
├── commands/
│   └── bug-hunt.md          # /bug-hunt skill definition
├── core/
│   ├── base_hunter.py       # BugFinding dataclass + BaseHunter ABC
│   ├── leaderboard.py       # Points system + persistence
│   └── bug_hunter_arena.py  # Arena runner + LLM Jury
├── hunters/
│   ├── data_boundary_hunter.py
│   ├── circular_state_hunter.py
│   ├── schema_hunter.py
│   ├── time_window_hunter.py
│   ├── process_hunter.py
│   └── signal_flow_hunter.py
├── adapters/
│   └── tradingbot_adapter.py
└── README.md
```

---

## License

MIT — use freely, contributions welcome.

---

*Built to solve real bugs in a cryptocurrency trading bot after months of paper-trading blockages caused by issues static analysis never caught.*
