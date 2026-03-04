"""
circular_state_hunter.py — Sucht A→B→A State-Deadlocks in State-Files.

Typisches Bug-Pattern:
  MCM liest density → density=0 wegen zu kleinem Zeitfenster → MCM=UNFAVORABLE
  → kein Trading → density bleibt 0 → MCM=UNFAVORABLE (Deadlock)

Methode: Analysiert State-Files (JSON) + State-Transitions in Code.

Open-Source Bug Hunter Arena — MIT License
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from core.base_hunter import BaseHunter, BugFinding
import logging

logger = logging.getLogger("bug_swarm")

# State-Files die auf Deadlocks geprüft werden
_STATE_FILE_PATTERNS = [
    "*.json",
    "*.jsonl",
]

# Verdächtige State-Werte die Deadlocks andeuten
_DEADLOCK_INDICATORS = {
    "direction": ["UNKNOWN", "unknown", ""],
    "market_condition": ["UNFAVORABLE", "unfavorable"],
    "regime": ["UNKNOWN", "unknown"],
    "density": [0, 0.0],
}

# State-Transition-Pattern im Code (A→B→A)
_CIRCULAR_PATTERNS = [
    ("UNFAVORABLE", "density", "0"),
    ("UNKNOWN", "direction", "not enough"),
    ("BLOCKED", "gate", "blocked"),
]


class CircularStateHunter(BaseHunter):
    """
    Sucht zirkuläre State-Deadlocks: A→B→A Feedback-Loops.

    Analysiert:
    1. State-Files auf steckengebliebene Werte (UNKNOWN, density=0)
    2. Code-Patterns die State-Abhängigkeiten erzeugen
    """

    name = "CircularStateHunter"
    specialty = "circular_state"
    description = "A→B→A State-Deadlocks (MCM→density→MCM, Direction→UNKNOWN→Direction)"

    def hunt(self, project_root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        findings.extend(self._scan_state_files(project_root))
        findings.extend(self._scan_code_patterns(project_root))
        return findings

    # ------------------------------------------------------------------
    # State-File Analyse
    # ------------------------------------------------------------------

    def _scan_state_files(self, root: Path) -> list[BugFinding]:
        """Scannt JSON-Dateien auf eingefrorne Deadlock-Werte."""
        findings: list[BugFinding] = []
        results_path = root / "results"
        if not results_path.exists():
            return findings

        for json_file in results_path.rglob("*.json"):
            if json_file.name.startswith("."):
                continue
            finding = self._check_json_state(json_file, root)
            if finding:
                findings.append(finding)
        return findings

    def _check_json_state(self, path: Path, root: Path) -> BugFinding | None:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

        rel_path = str(path.relative_to(root))

        for key, bad_values in _DEADLOCK_INDICATORS.items():
            value = data.get(key)
            if value in bad_values:
                return self._make_finding(
                    severity="high",
                    file_path=rel_path,
                    line_number=None,
                    description=(
                        f"State-File enthält Deadlock-Indikator: {key}={value!r} "
                        f"→ könnte auf eingefroren State hindeuten"
                    ),
                    evidence=f"{key}: {value!r} in {path.name}",
                    suggested_fix=(
                        f"Prüfe ob {key}={value!r} ein dauerhafter Zustand ist. "
                        f"Falls ja: Reset-Mechanismus implementieren. "
                        f"Prüfe ob der Schreib-Pfad korrekt ist (kein altes Cache-File)."
                    ),
                )
        return None

    # ------------------------------------------------------------------
    # Code-Pattern Analyse
    # ------------------------------------------------------------------

    def _scan_code_patterns(self, root: Path) -> list[BugFinding]:
        """Sucht Code-Patterns die zirkuläre Abhängigkeiten erzeugen."""
        findings: list[BugFinding] = []
        # MCM-relevante Dateien prüfen
        mcm_files = list(root.rglob("*market_condition*.py"))
        analyzer_files = list(root.rglob("*analyzer*.py"))
        for py_file in mcm_files + analyzer_files:
            if self._should_skip(py_file, root):
                continue
            findings.extend(self._check_circular_reads(py_file, root))
        return findings

    def _check_circular_reads(self, path: Path, root: Path) -> list[BugFinding]:
        """Prüft ob MCM-Output als eigener Input genutzt wird (A→B→A)."""
        findings: list[BugFinding] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        rel_path = str(path.relative_to(root))
        lines = source.splitlines()

        # Suche: MCM-State wird gelesen UND MCM wird danach direkt beeinflusst
        reads_mcm = any("get_current_state" in line or "mcm_state" in line for line in lines)
        writes_mcm = any("market_bias" in line and "=" in line for line in lines)

        if reads_mcm and writes_mcm:
            # Suche Zeile wo market_bias geschrieben wird
            for i, line in enumerate(lines, 1):
                if "market_bias" in line and "=" in line and "==" not in line:
                    findings.append(self._make_finding(
                        severity="medium",
                        file_path=rel_path,
                        line_number=i,
                        description=(
                            "Möglicher Circular-State: MCM-State gelesen UND "
                            "market_bias geschrieben in gleicher Datei → A→B→A Deadlock möglich"
                        ),
                        evidence=line.strip(),
                        suggested_fix=(
                            "Stelle sicher dass MCM-Reads und MCM-Writes "
                            "nicht in einer Feedback-Schleife liegen. "
                            "MCM sollte READ-ONLY sein (per CLAUDE.md)."
                        ),
                    ))
                    break  # Nur erste Fundstelle

        return findings

    def _should_skip(self, path: Path, root: Path) -> bool:
        skip = {"venv", "venv_win", ".git", "__pycache__", "tests"}
        return any(part in skip for part in path.parts)
