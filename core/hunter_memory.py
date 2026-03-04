"""
hunter_memory.py — Persistent learning memory for Bug Swarm Hunters.

Prevents known false positives from being re-reported on every run.
Tracks hunter precision over time.

Persistence: {project_root}/.bug_hunters/memory.json
Finding hash: SHA256(hunter_name + ":" + file_path + ":" + evidence[:100])

Bug Swarm Hunters — MIT License
https://github.com/svensteiner/Bug-swarm-hunters
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.base_hunter import BugFinding

logger = logging.getLogger("bug_swarm.memory")

_MEMORY_VERSION = "1.0"


class HunterMemory:
    """
    Stores jury verdicts and prevents FP repetition.

    Findings are identified by SHA256 hash (without line_number,
    since that changes after code edits).
    """

    def __init__(self, storage_dir: Path) -> None:
        self._path = storage_dir / "memory.json"
        self._data: dict = {"version": _MEMORY_VERSION, "findings": {}, "hunter_stats": {}}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_known_fp(self, finding: "BugFinding") -> bool:
        """True if this finding is known as a false positive."""
        h = self.finding_hash(finding)
        entry = self._data["findings"].get(h)
        if entry is None:
            return False
        return entry.get("verdict") == "false_positive"

    def remember_verdict(self, finding: "BugFinding", verdict: str) -> None:
        """
        Store a jury verdict for a finding.

        Args:
            finding: The evaluated finding.
            verdict: "confirmed" or "false_positive".
        """
        h = self.finding_hash(finding)
        today = date.today().isoformat()
        existing = self._data["findings"].get(h)
        if existing:
            existing["verdict"] = verdict
            existing["verdict_count"] = existing.get("verdict_count", 1) + 1
            existing["last_seen"] = today
        else:
            self._data["findings"][h] = {
                "hunter_name": finding.hunter_name,
                "file_path": finding.file_path,
                "evidence_snippet": finding.evidence[:100],
                "verdict": verdict,
                "verdict_count": 1,
                "first_seen": today,
                "last_seen": today,
            }
        self._update_stats(finding.hunter_name, verdict)

    def get_hunter_precision(self, name: str) -> float:
        """Hunter precision: confirmed / (confirmed + false_positives). 0.0–1.0."""
        stats = self._data["hunter_stats"].get(name, {})
        confirmed = stats.get("confirmed", 0)
        fps = stats.get("false_positives", 0)
        total = confirmed + fps
        return confirmed / total if total > 0 else 1.0  # Unknown hunters: full trust

    def get_stats_summary(self) -> str:
        """Returns a human-readable summary of hunter precision."""
        stats = self._data.get("hunter_stats", {})
        if not stats:
            return "No memory statistics yet (first run?)"
        lines = ["Hunter precision (memory):"]
        for name, s in sorted(stats.items()):
            total = s.get("confirmed", 0) + s.get("false_positives", 0)
            precision = self.get_hunter_precision(name)
            lines.append(
                f"  {name}: {precision:.0%} "
                f"({s.get('confirmed', 0)} confirmed / {s.get('false_positives', 0)} FP / {total} total)"
            )
        known_fps = sum(
            1 for e in self._data.get("findings", {}).values()
            if e.get("verdict") == "false_positive"
        )
        lines.append(f"  Known FPs total: {known_fps} (filtered on next run)")
        return "\n".join(lines)

    def save(self) -> None:
        """Save memory to JSON file."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2, ensure_ascii=False)
            logger.debug("[MEMORY] Saved: %s", self._path)
        except (OSError, ValueError) as exc:
            logger.warning("[MEMORY] Save failed: %s", exc)

    @staticmethod
    def finding_hash(finding: "BugFinding") -> str:
        """
        SHA256 hash of a finding without line_number.

        Stable after code edits that only shift line numbers.
        """
        key = f"{finding.hunter_name}:{finding.file_path}:{finding.evidence[:100]}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load memory from JSON (ignores errors -> start fresh)."""
        if not self._path.exists():
            return
        try:
            with open(self._path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict) and "findings" in loaded:
                self._data = loaded
                logger.debug("[MEMORY] Loaded: %d entries", len(self._data["findings"]))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("[MEMORY] Load failed, starting fresh: %s", exc)

    def _update_stats(self, hunter_name: str, verdict: str) -> None:
        stats = self._data["hunter_stats"].setdefault(hunter_name, {
            "total_findings": 0,
            "confirmed": 0,
            "false_positives": 0,
            "precision": 1.0,
        })
        stats["total_findings"] = stats.get("total_findings", 0) + 1
        if verdict == "confirmed":
            stats["confirmed"] = stats.get("confirmed", 0) + 1
        elif verdict == "false_positive":
            stats["false_positives"] = stats.get("false_positives", 0) + 1
        total = stats["confirmed"] + stats["false_positives"]
        stats["precision"] = stats["confirmed"] / total if total > 0 else 1.0
