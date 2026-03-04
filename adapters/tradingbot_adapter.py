"""
tradingbot_adapter.py — Adapter for trading bot projects.

Routes bug proposals to results/proposals/ (governance-compliant)
instead of the default bug_hunt_proposals/ directory.

Usage:
    from adapters.tradingbot_adapter import run_tradingbot_hunt
    result = run_tradingbot_hunt(project_root=Path("."))
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from core.bug_hunter_arena import BugHunterArena, ArenaResult
from core.base_hunter import BaseHunter, BugFinding

logger = logging.getLogger("bug_swarm.tradingbot")


class TradingBotArena(BugHunterArena):
    """
    Bug Hunter Arena adapted for trading bot projects.

    Differences from base:
    - Proposals go to results/proposals/ (governance-compliant)
    - Proposal format matches trading bot governance schema
    - Leaderboard in results/.bug_hunters/
    """

    def __init__(self, project_root: Path) -> None:
        from core.leaderboard import Leaderboard
        self._root = project_root
        results = project_root / "results"
        self._leaderboard = Leaderboard(results / ".bug_hunters")

    def _write_proposals(self, findings: list[BugFinding]) -> int:
        """Write governance-compliant proposals to results/proposals/."""
        proposals_dir = self._root / "results" / "proposals"
        proposals_dir.mkdir(parents=True, exist_ok=True)
        written = 0
        for i, f in enumerate(findings):
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            proposal_id = f"bug_{f.hunter_name}_{ts}_{i}"
            proposal = {
                "proposal_id": proposal_id,
                "source": "bug_swarm_hunters",
                "created_at": datetime.utcnow().isoformat(),
                "status": "OPEN",
                "type": "BUG_FINDING",
                "hunter": f.hunter_name,
                "severity": f.severity,
                "category": f.category,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "description": f.description,
                "evidence": f.evidence[:500],
                "suggested_fix": f.suggested_fix,
                "governance_note": (
                    "BUG HUNTER FINDING — Manual review required. "
                    "No automatic config changes."
                ),
            }
            try:
                path = proposals_dir / f"proposal_{proposal_id}.json"
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(proposal, fh, indent=2, ensure_ascii=False)
                written += 1
            except (OSError, ValueError) as exc:
                logger.warning("Proposal write failed: %s", exc)
        return written


def run_tradingbot_hunt(
    project_root: Path | None = None,
    use_llm_jury: bool = True,
) -> ArenaResult:
    """Run arena with trading bot adapter."""
    from hunters.data_boundary_hunter import DataBoundaryHunter
    from hunters.circular_state_hunter import CircularStateHunter
    from hunters.schema_hunter import SchemaHunter
    from hunters.time_window_hunter import TimeWindowHunter
    from hunters.process_hunter import ProcessHunter
    from hunters.signal_flow_hunter import SignalFlowHunter

    root = project_root or Path(".").resolve()
    hunters: list[BaseHunter] = [
        DataBoundaryHunter(),
        CircularStateHunter(),
        SchemaHunter(),
        TimeWindowHunter(),
        ProcessHunter(),
        SignalFlowHunter(),
    ]
    arena = TradingBotArena(root)
    return arena.run(hunters, use_llm_jury=use_llm_jury, write_proposals=True)
