"""
base_hunter.py — Abstract base for all Bug Hunter agents.

Each hunter specializes in one class of runtime bugs and returns
a list of BugFinding instances.

Bug Swarm Hunters — MIT License
https://github.com/svensteiner/Bug-swarm-hunters
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("bug_swarm")


@dataclass
class BugFinding:
    hunter_name: str
    severity: str          # "critical" | "high" | "medium" | "low"
    category: str          # e.g. "data_boundary", "circular_state"
    file_path: str         # relative to project_root
    line_number: int | None
    description: str
    evidence: str          # code snippet or log line
    suggested_fix: str
    confirmed: bool = False
    auto_fixed: bool = False
    false_positive: bool = False

    def to_dict(self) -> dict:
        return {
            "hunter_name": self.hunter_name,
            "severity": self.severity,
            "category": self.category,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "description": self.description,
            "evidence": self.evidence[:500],
            "suggested_fix": self.suggested_fix,
            "confirmed": self.confirmed,
            "auto_fixed": self.auto_fixed,
            "false_positive": self.false_positive,
        }

    def __str__(self) -> str:
        loc = f":{self.line_number}" if self.line_number else ""
        return f"[{self.severity.upper()}] {self.hunter_name} -> {self.file_path}{loc}: {self.description}"


class BaseHunter(ABC):
    """
    Abstract base for all Bug Hunter agents.

    Subclasses must define `name`, `specialty`, `description` and `hunt()`.
    `hunt_safe()` catches all exceptions and returns an empty list.
    """

    name: str
    specialty: str
    description: str

    @abstractmethod
    def hunt(self, project_root: Path) -> list[BugFinding]:
        """
        Actively search for bugs in the given project root.

        Args:
            project_root: Root directory of the project to scan.

        Returns:
            List of BugFinding instances (may be empty).
        """
        ...

    def hunt_safe(self, project_root: Path) -> list[BugFinding]:
        """Like hunt(), but catches all exceptions."""
        try:
            findings = self.hunt(project_root)
            logger.debug("[%s] %d findings", self.name, len(findings))
            return findings
        except Exception as exc:
            logger.warning("[%s] Hunt failed: %s", self.name, exc)
            return []

    def _make_finding(
        self,
        severity: str,
        file_path: str,
        line_number: int | None,
        description: str,
        evidence: str,
        suggested_fix: str,
    ) -> BugFinding:
        return BugFinding(
            hunter_name=self.name,
            severity=severity,
            category=self.specialty,
            file_path=file_path,
            line_number=line_number,
            description=description,
            evidence=evidence,
            suggested_fix=suggested_fix,
        )
