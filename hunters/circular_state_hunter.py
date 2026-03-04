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
    # Code-Pattern Analysis (Cross-File 2-Hop Graph)
    # ------------------------------------------------------------------

    # Known state names in trading-bot context (adapt for your project)
    _STATE_WRITERS = {"market_bias", "mcm_state", "density", "regime"}
    _STATE_READERS = {"get_current_state", "get_mcm_state", "mcm_state", "market_bias"}

    def _scan_code_patterns(self, root: Path) -> list[BugFinding]:
        """
        Cross-file 2-hop graph: finds A->B->A cycles across multiple files.

        Step 1: Which files write which state?
        Step 2: Which files read that state AND write another?
        Step 3: Is there an A->B->A cycle?
        """
        findings: list[BugFinding] = []

        # Build state map: {file: {reads: set, writes: set}}
        file_states: dict[str, dict[str, set[str]]] = {}

        py_files = [f for f in root.rglob("*.py") if not self._should_skip(f, root)]

        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(py_file.relative_to(root))
            reads: set[str] = set()
            writes: set[str] = set()
            for line in source.splitlines():
                for reader in self._STATE_READERS:
                    if reader in line:
                        reads.add(reader)
                for writer in self._STATE_WRITERS:
                    if writer in line and "=" in line and "==" not in line and "#" not in line.split("=")[0]:
                        writes.add(writer)
            if reads or writes:
                file_states[rel] = {"reads": reads, "writes": writes}

        # Find cross-file A->B->A cycles
        findings.extend(self._find_cross_file_cycles(file_states, root))

        # Single-file circular state (read + write same variable)
        for rel, states in file_states.items():
            cross = states["reads"] & states["writes"]
            if cross:
                py_file = root / rel
                findings.extend(self._check_single_file_circular(py_file, root, cross))

        return findings

    def _find_cross_file_cycles(
        self,
        file_states: dict[str, dict[str, set[str]]],
        root: Path,
    ) -> list[BugFinding]:
        """Find A->B->A cycles in the cross-file state graph."""
        findings: list[BugFinding] = []
        files = list(file_states.keys())

        for file_a in files:
            writes_a = file_states[file_a]["writes"]
            if not writes_a:
                continue
            for file_b in files:
                if file_b == file_a:
                    continue
                reads_b = file_states[file_b]["reads"]
                writes_b = file_states[file_b]["writes"]
                shared_a_to_b = writes_a & reads_b
                if not shared_a_to_b:
                    continue
                reads_a = file_states[file_a]["reads"]
                shared_b_to_a = writes_b & reads_a
                if not shared_b_to_a:
                    continue
                # Real cross-file cycle found
                cycle_desc = (
                    f"{file_a} writes {shared_a_to_b} -> "
                    f"{file_b} reads + writes {shared_b_to_a} -> "
                    f"{file_a} reads (A->B->A cycle)"
                )
                findings.append(self._make_finding(
                    severity="high",
                    file_path=file_a,
                    line_number=None,
                    description=f"Cross-file circular state: {cycle_desc}",
                    evidence=f"A={file_a} <-> B={file_b} via {shared_a_to_b | shared_b_to_a}",
                    suggested_fix=(
                        "Separate read and write access to state variables into different layers. "
                        "MCM should be READ-ONLY. State writes should be in a single central file."
                    ),
                ))
        return findings

    def _check_single_file_circular(
        self, path: Path, root: Path, circular_states: set[str]
    ) -> list[BugFinding]:
        """Check single file for read+write of the same state variable."""
        findings: list[BugFinding] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings
        rel_path = str(path.relative_to(root))
        lines = source.splitlines()
        for state in circular_states:
            for i, line in enumerate(lines, 1):
                if state in line and "=" in line and "==" not in line and "#" not in line.split("=")[0]:
                    findings.append(self._make_finding(
                        severity="medium",
                        file_path=rel_path,
                        line_number=i,
                        description=(
                            f"Possible circular state: '{state}' is read AND written "
                            "in the same file -> A->B->A deadlock possible"
                        ),
                        evidence=line.strip(),
                        suggested_fix=(
                            "Ensure that state reads and writes are not in a feedback loop. "
                            "MCM should be READ-ONLY."
                        ),
                    ))
                    break  # Only first occurrence per state
        return findings

    def _should_skip(self, path: Path, root: Path) -> bool:
        skip = {"venv", "venv_win", ".git", "__pycache__", "tests"}
        return any(part in skip for part in path.parts)
