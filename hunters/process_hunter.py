"""
process_hunter.py — Sucht subprocess/Process ohne cleanup via AST.

Typisches Bug-Pattern:
  p = multiprocessing.Process(target=worker)
  p.start()
  # kein p.terminate() in finally-Block → Zombie-Process auf Windows

Windows killt Child-Processes NICHT automatisch wenn Parent stirbt.
Dies war der Root-Cause des Trader-Exit-Bugs (MEMORY.md).

Open-Source Bug Hunter Arena — MIT License
"""
from __future__ import annotations

import ast
from pathlib import Path

from core.base_hunter import BaseHunter, BugFinding
import logging

logger = logging.getLogger("bug_swarm")

# Process-Typen die cleanup benötigen
_PROCESS_TYPES = {
    "Process",          # multiprocessing.Process
    "Thread",           # threading.Thread
    "Popen",            # subprocess.Popen
}

# Cleanup-Methoden die als ausreichend gelten
_CLEANUP_METHODS = {"terminate", "kill", "join", "wait", "close"}


class ProcessHunter(BaseHunter):
    """
    Sucht Process()/Thread()-Instanziierungen ohne terminate() in finally-Block.

    Besonders kritisch auf Windows: keine automatische Child-Termination
    wenn Parent-Process stirbt → Zombie-Processes die DB und State blockieren.
    """

    name = "ProcessHunter"
    specialty = "process_leak"
    description = "Process/Thread ohne terminate() in finally → Zombie-Processes auf Windows"

    def hunt(self, project_root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        for py_file in project_root.rglob("*.py"):
            if self._should_skip(py_file, project_root):
                continue
            findings.extend(self._scan_file(py_file, project_root))
        return findings

    def _should_skip(self, path: Path, root: Path) -> bool:
        skip = {"venv", "venv_win", ".git", "__pycache__", "tests", "hunters"}
        return any(part in skip for part in path.parts)

    def _scan_file(self, path: Path, root: Path) -> list[BugFinding]:
        findings: list[BugFinding] = []
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, OSError):
            return findings

        rel_path = str(path.relative_to(root))
        lines = source.splitlines()

        # Suche Funktionen/Methoden die Processes erstellen
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            findings.extend(self._check_function(node, lines, rel_path))

        return findings

    def _check_function(
        self, func: ast.FunctionDef, lines: list[str], rel_path: str
    ) -> list[BugFinding]:
        """Prüft eine Funktion auf Process-Erstllungen ohne Cleanup."""
        findings: list[BugFinding] = []

        # Sammle alle Process-Starts in dieser Funktion
        process_starts = self._find_process_starts(func)
        if not process_starts:
            return findings

        # Prüfe ob Try/Finally mit Cleanup vorhanden
        has_cleanup = self._has_process_cleanup(func)

        if not has_cleanup:
            for process_name, lineno in process_starts:
                line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
                findings.append(self._make_finding(
                    severity="high",
                    file_path=rel_path,
                    line_number=lineno,
                    description=(
                        f"{process_name} gestartet ohne terminate() in finally-Block "
                        f"→ Zombie-Process auf Windows möglich"
                    ),
                    evidence=line_text,
                    suggested_fix=(
                        f"Umhülle mit try/finally:\n"
                        f"  p = {process_name}(...)\n"
                        f"  p.start()\n"
                        f"  try:\n"
                        f"      ...\n"
                        f"  finally:\n"
                        f"      p.terminate()\n"
                        f"      p.join(timeout=5)\n"
                        f"Oder: nutze daemon=True für Hintergrund-Threads."
                    ),
                ))

        return findings

    def _find_process_starts(
        self, func: ast.FunctionDef
    ) -> list[tuple[str, int]]:
        """Findet alle process.start() Aufrufe in einer Funktion."""
        starts: list[tuple[str, int]] = []
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            # process.start()
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "start":
                continue
            # Prüfe ob Variable ein Process-Typ ist
            var_name = ""
            if isinstance(node.func.value, ast.Name):
                var_name = node.func.value.id
            # Ist es ein bekannter Process-Typ (in Zuweisung vorher)?
            lineno = getattr(node, "lineno", 0)
            starts.append((var_name or "Process", lineno))
        return starts

    def _has_process_cleanup(self, func: ast.FunctionDef) -> bool:
        """Prüft ob eine try/finally-Cleanup-Struktur vorhanden ist."""
        for node in ast.walk(func):
            if not isinstance(node, ast.Try):
                continue
            # Prüfe finally-Block auf cleanup-Methoden
            for finally_node in node.finalbody:
                for sub in ast.walk(finally_node):
                    if isinstance(sub, ast.Call):
                        if isinstance(sub.func, ast.Attribute):
                            if sub.func.attr in _CLEANUP_METHODS:
                                return True
                    # terminate() direkt
                    if isinstance(sub, ast.Expr) and isinstance(sub.value, ast.Call):
                        call = sub.value
                        if isinstance(call.func, ast.Attribute):
                            if call.func.attr in _CLEANUP_METHODS:
                                return True
        return False
