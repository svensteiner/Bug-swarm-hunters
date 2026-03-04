"""
bug_hunter_arena.py — Arena runner + LLM Jury for Bug Swarm Hunters.

Workflow:
  1. All hunters run in parallel (ThreadPoolExecutor)
  2. LLM Jury: confirm or mark as false positive
  3. Award points + update leaderboard
  4. Write proposals for confirmed bugs
  5. Return ArenaResult

Bug Swarm Hunters — MIT License
https://github.com/svensteiner/Bug-swarm-hunters
"""
from __future__ import annotations

import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from core.base_hunter import BaseHunter, BugFinding
from core.leaderboard import Leaderboard

logger = logging.getLogger("bug_swarm.arena")


@dataclass
class ArenaResult:
    total_findings: int
    confirmed: int
    false_positives: int
    unverified: int
    proposals_written: int
    leaderboard_summary: str
    findings: list[BugFinding] = field(default_factory=list)
    duration_seconds: float = 0.0

    def __str__(self) -> str:
        return (
            f"Bug Hunt: {self.total_findings} findings "
            f"({self.confirmed} confirmed, {self.false_positives} FP, "
            f"{self.unverified} unverified) | "
            f"{self.proposals_written} proposals | "
            f"{self.duration_seconds:.1f}s"
        )


class BugHunterArena:
    """
    Coordinates multiple BaseHunter instances in parallel runs,
    lets an LLM Jury vote on findings, and awards points.
    """

    def __init__(self, project_root: Path) -> None:
        self._root = project_root
        self._leaderboard = Leaderboard(project_root / ".bug_hunters")

    def run(
        self,
        hunters: list[BaseHunter],
        use_llm_jury: bool = True,
        write_proposals: bool = True,
    ) -> ArenaResult:
        t_start = time.time()
        logger.info("[ARENA] Starting with %d hunters, root=%s", len(hunters), self._root)

        # Phase 1: Parallel hunt
        all_findings = self._run_hunters_parallel(hunters)
        logger.info("[ARENA] %d raw findings collected", len(all_findings))

        # Phase 2: LLM Jury
        if use_llm_jury:
            all_findings = self._llm_jury(all_findings)
        else:
            for f in all_findings:
                f.confirmed = True

        confirmed = [f for f in all_findings if f.confirmed and not f.false_positive]
        false_pos = [f for f in all_findings if f.false_positive]
        unverified = [f for f in all_findings if not f.confirmed and not f.false_positive]

        # Phase 3: Points
        self._award_points(confirmed, false_pos)

        # Phase 4: Proposals
        proposals_written = 0
        if write_proposals and confirmed:
            proposals_written = self._write_proposals(confirmed)
            for f in confirmed:
                f.auto_fixed = True
                self._leaderboard.award_auto_fixed(f.hunter_name)

        self._leaderboard.save()

        result = ArenaResult(
            total_findings=len(all_findings),
            confirmed=len(confirmed),
            false_positives=len(false_pos),
            unverified=len(unverified),
            proposals_written=proposals_written,
            leaderboard_summary=self._leaderboard.format_top3(),
            findings=all_findings,
            duration_seconds=time.time() - t_start,
        )
        logger.info("[ARENA] %s", result)
        return result

    def _run_hunters_parallel(self, hunters: list[BaseHunter]) -> list[BugFinding]:
        all_findings: list[BugFinding] = []
        with ThreadPoolExecutor(max_workers=min(len(hunters), 6), thread_name_prefix="hunter") as ex:
            futures = {ex.submit(h.hunt_safe, self._root): h for h in hunters}
            for fut in as_completed(futures):
                h = futures[fut]
                try:
                    findings = fut.result(timeout=60)
                    all_findings.extend(findings)
                    logger.debug("[ARENA] %s: %d findings", h.name, len(findings))
                except Exception as exc:
                    logger.warning("[ARENA] %s future failed: %s", h.name, exc)
        return all_findings

    def _llm_jury(self, findings: list[BugFinding]) -> list[BugFinding]:
        """LLM evaluates findings. Without API key -> all marked as confirmed."""
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key or not api_key.startswith("sk-"):
            logger.info("[ARENA] No OPENAI_API_KEY — jury skipped (unverified)")
            for f in findings:
                f.confirmed = True
            return findings

        model = os.getenv("LLM_FAST_MODEL", "gpt-4.1-mini")
        try:
            return self._call_llm_jury(findings, api_key, model)
        except Exception as exc:
            logger.warning("[ARENA] LLM jury failed: %s — all confirmed", exc)
            for f in findings:
                f.confirmed = True
            return findings

    def _call_llm_jury(
        self, findings: list[BugFinding], api_key: str, model: str
    ) -> list[BugFinding]:
        import urllib.request
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        for finding in findings[:10]:
            verdict = self._jury_single(finding, headers, model)
            finding.confirmed = verdict != "false_positive"
            finding.false_positive = verdict == "false_positive"
        for finding in findings[10:]:
            finding.confirmed = True
        return findings

    def _jury_single(self, f: BugFinding, headers: dict, model: str) -> str:
        import urllib.request
        prompt = (
            f"You are a Python code review expert. Evaluate this bug report:\n\n"
            f"Hunter: {f.hunter_name}\n"
            f"Category: {f.category}\n"
            f"File: {f.file_path}:{f.line_number}\n"
            f"Description: {f.description}\n"
            f"Evidence: {f.evidence[:300]}\n\n"
            f"Reply ONLY with: CONFIRMED or FALSE_POSITIVE"
        )
        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 20,
            "temperature": 0.1,
        }).encode()
        try:
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=payload,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                text = data["choices"][0]["message"]["content"].strip().upper()
                return "false_positive" if "FALSE_POSITIVE" in text else "confirmed"
        except Exception as exc:
            logger.debug("LLM jury call failed: %s", exc)
            return "confirmed"

    def _award_points(
        self, confirmed: list[BugFinding], false_pos: list[BugFinding]
    ) -> None:
        for f in confirmed:
            self._leaderboard.award_confirmed(f.hunter_name, f.severity)
        for f in false_pos:
            self._leaderboard.penalize_false_positive(f.hunter_name)

    def _write_proposals(self, findings: list[BugFinding]) -> int:
        proposals_dir = self._root / "bug_hunt_proposals"
        proposals_dir.mkdir(parents=True, exist_ok=True)
        written = 0
        for i, f in enumerate(findings):
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            proposal_id = f"bug_{f.hunter_name}_{ts}_{i}"
            proposal = {
                "proposal_id": proposal_id,
                "created_at": datetime.utcnow().isoformat(),
                "status": "OPEN",
                "hunter": f.hunter_name,
                "severity": f.severity,
                "category": f.category,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "description": f.description,
                "evidence": f.evidence[:500],
                "suggested_fix": f.suggested_fix,
            }
            try:
                path = proposals_dir / f"proposal_{proposal_id}.json"
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(proposal, fh, indent=2, ensure_ascii=False)
                written += 1
            except (OSError, ValueError) as exc:
                logger.warning("Proposal write failed: %s", exc)
        return written


def run_arena(
    project_root: Path | None = None,
    use_llm_jury: bool = True,
    write_proposals: bool = True,
) -> ArenaResult:
    """
    Run the full arena with all 6 hunters.

    Args:
        project_root: Project directory to scan (default: current directory).
        use_llm_jury: Enable LLM-based verification.
        write_proposals: Write proposal files for confirmed bugs.

    Returns:
        ArenaResult with stats and leaderboard.
    """
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
    arena = BugHunterArena(root)
    return arena.run(hunters, use_llm_jury=use_llm_jury, write_proposals=write_proposals)
