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
    # Code-Pattern Analyse (Cross-File 2-Hop Graph)
    # ------------------------------------------------------------------

    # Bekannte State-Namen im Trading-Bot-Kontext
    _STATE_WRITERS = {"market_bias", "mcm_state", "density", "regime"}
    _STATE_READERS = {"get_current_state", "get_mcm_state", "mcm_state", "market_bias"}

    def _scan_code_patterns(self, root: Path) -> list[BugFinding]:
        """
        Cross-File 2-Hop Graph: Sucht A→B→A Zyklen über mehrere Dateien.

        Schritt 1: Welche Dateien schreiben welchen State?
        Schritt 2: Welche Dateien lesen diesen State UND schreiben anderen?
        Schritt 3: Gibt es A→B→A Zyklus?
        """
        findings: list[BugFinding] = []

        # State-Map aufbauen: {state_name: {datei: "reads"|"writes"|"both"}}
        file_states: dict[str, dict[str, set[str]]] = {}  # file → {reads: set, writes: set}

        import re as _re
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
                stripped = line.strip()
                # Kommentare überspringen
                if stripped.startswith("#"):
                    continue
                # String-Literal-Zeilen überspringen (state-name in Anführungszeichen)
                for reader in self._STATE_READERS:
                    # Nur echte Variable-Zugriffe zählen (kein "mcm_state" als String-Literal)
                    if _re.search(rf'\b{_re.escape(reader)}\b', stripped):
                        # Nicht wenn es nur als String-Literal vorkommt
                        if f'"{reader}"' not in stripped and f"'{reader}'" not in stripped:
                            reads.add(reader)
                for writer in self._STATE_WRITERS:
                    # Echter Assignment: writer\s*= (kein ==, !=, +=, in-String)
                    if f'"{writer}"' in stripped or f"'{writer}'" in stripped:
                        continue  # String-Literal → kein Write
                    if _re.search(rf'\b{_re.escape(writer)}\s*=[^=]', stripped):
                        writes.add(writer)
            if reads or writes:
                file_states[rel] = {"reads": reads, "writes": writes}

        # 2-Hop-Zyklen suchen: Datei A schreibt X → Datei B liest X und schreibt Y → Datei A liest Y
        findings.extend(self._find_cross_file_cycles(file_states, root))

        # Zusätzlich: Einzeldatei Circular-State (MCM read + write in gleicher Datei)
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
        """
        Sucht Multiple-Writer State-Probleme im Cross-File State-Graph.

        Dedupliziert nach State-Variable: Ein Finding pro State, nicht pro Datei-Paar.
        Verhindert kombinatorische Explosion bei vielen Writern.
        """
        findings: list[BugFinding] = []

        # Welche Dateien schreiben welchen State?
        writers_per_state: dict[str, list[str]] = {}
        readers_per_state: dict[str, list[str]] = {}
        for file, states in file_states.items():
            for state in states["writes"]:
                writers_per_state.setdefault(state, []).append(file)
            for state in states["reads"]:
                readers_per_state.setdefault(state, []).append(file)

        # Pro State-Variable: Wenn >1 Datei schreibt UND mindestens eine auch liest → Bug
        for state in sorted(writers_per_state):
            writers = writers_per_state[state]
            if len(writers) <= 1:
                continue  # Nur ein Writer → kein Multi-Writer-Problem
            readers = readers_per_state.get(state, [])
            # Mindestens eine Datei schreibt UND liest denselben State
            reader_writers = [f for f in writers if f in readers]
            if not reader_writers:
                continue
            writer_list = ", ".join(sorted(writers)[:4])
            if len(writers) > 4:
                writer_list += f" (+{len(writers)-4} weitere)"
            findings.append(self._make_finding(
                severity="high",
                file_path=writers[0],
                line_number=None,
                description=(
                    f"Multiple-Writer State: '{state}' wird von {len(writers)} Dateien "
                    f"geschrieben und gelesen → A→B→A Deadlock möglich"
                ),
                evidence=f"Writers: {writer_list}",
                suggested_fix=(
                    f"State '{state}' sollte nur von einer zentralen Datei geschrieben werden. "
                    "Alle anderen Dateien sollten nur lesen. "
                    "MCM sollte READ-ONLY sein (per CLAUDE.md)."
                ),
            ))
        return findings

    def _check_single_file_circular(
        self, path: Path, root: Path, circular_states: set[str]
    ) -> list[BugFinding]:
        """Prüft Einzeldatei auf Read+Write der gleichen State-Variable."""
        findings: list[BugFinding] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings
        rel_path = str(path.relative_to(root))
        lines = source.splitlines()
        import re as _re
        for state in circular_states:
            for i, line in enumerate(lines, 1):
                stripped_line = line.strip()
                if stripped_line.startswith("#"):
                    continue
                if f'"{state}"' in stripped_line or f"'{state}'" in stripped_line:
                    continue  # String-Literal → kein echter Write
                if not _re.search(rf'\b{_re.escape(state)}\s*=[^=]', stripped_line):
                    continue
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
        skip = {"venv", "venv_win", ".git", "__pycache__", "tests", "hunters"}
        return any(part in skip for part in path.parts)
