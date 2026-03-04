"""
leaderboard.py — Points system and persistence for Bug Swarm Hunters.

Scoring:
  +10  Bug confirmed (LLM Jury)
  +5   Bug auto-fixed (proposal written)
  -3   False positive
  x2   Severity bonus for "critical"

Persistence: {project_root}/.bug_hunters/leaderboard.json

Bug Swarm Hunters — MIT License
https://github.com/svensteiner/Bug-swarm-hunters
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("bug_swarm.leaderboard")

POINTS_CONFIRMED = 10
POINTS_AUTO_FIXED = 5
POINTS_FALSE_POSITIVE = -3
POINTS_CRITICAL_MULTIPLIER = 2


@dataclass
class HunterScore:
    name: str
    points: int = 0
    confirmed_bugs: int = 0
    auto_fixed: int = 0
    false_positives: int = 0
    rank: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "HunterScore":
        return cls(
            name=data["name"],
            points=data.get("points", 0),
            confirmed_bugs=data.get("confirmed_bugs", 0),
            auto_fixed=data.get("auto_fixed", 0),
            false_positives=data.get("false_positives", 0),
            rank=data.get("rank", 0),
        )


class Leaderboard:
    """Manages hunter scores and persists to leaderboard.json."""

    def __init__(self, storage_dir: Path) -> None:
        self._dir = storage_dir
        self._path = storage_dir / "leaderboard.json"
        self._scores: dict[str, HunterScore] = {}
        self._load()

    def award_confirmed(self, hunter_name: str, severity: str) -> int:
        pts = POINTS_CONFIRMED
        if severity.lower() == "critical":
            pts *= POINTS_CRITICAL_MULTIPLIER
        s = self._get_or_create(hunter_name)
        s.points += pts
        s.confirmed_bugs += 1
        return pts

    def award_auto_fixed(self, hunter_name: str) -> int:
        s = self._get_or_create(hunter_name)
        s.points += POINTS_AUTO_FIXED
        s.auto_fixed += 1
        return POINTS_AUTO_FIXED

    def penalize_false_positive(self, hunter_name: str) -> int:
        s = self._get_or_create(hunter_name)
        s.points += POINTS_FALSE_POSITIVE
        s.false_positives += 1
        return POINTS_FALSE_POSITIVE

    def get_ranked(self) -> list[HunterScore]:
        ranked = sorted(self._scores.values(), key=lambda s: s.points, reverse=True)
        for i, s in enumerate(ranked):
            s.rank = i + 1
        return ranked

    def save(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        data = {
            "updated_at": datetime.utcnow().isoformat(),
            "scores": [s.to_dict() for s in self.get_ranked()],
        }
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except OSError as exc:
            logger.warning("Leaderboard save failed: %s", exc)

    def format_top3(self) -> str:
        ranked = self.get_ranked()[:3]
        if not ranked:
            return "Leaderboard empty — no hunt runs yet."
        lines = ["Bug Swarm Hunters Leaderboard (Top 3):"]
        medals = ["#1", "#2", "#3"]
        for i, s in enumerate(ranked):
            lines.append(
                f"  {medals[i]} {s.name}: {s.points}pts "
                f"({s.confirmed_bugs} bugs, {s.auto_fixed} fixes, {s.false_positives} FP)"
            )
        return "\n".join(lines)

    def _get_or_create(self, name: str) -> HunterScore:
        if name not in self._scores:
            self._scores[name] = HunterScore(name=name)
        return self._scores[name]

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("scores", []):
                s = HunterScore.from_dict(entry)
                self._scores[s.name] = s
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            logger.warning("Leaderboard load failed: %s", exc)
